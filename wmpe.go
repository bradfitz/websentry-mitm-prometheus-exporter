// The websentry-mitm-prometheus-exporter is a MITM proxy server
// for the WebSentry port 1030 protocol between WebSentry-capable
// dehumidifiers (see https://dehumidifiedairsolutions.com/) and
// its cloud service (TCP websentry.seresco.net:1030).
//
// Assuming you set up DHCP + iptables to intercept the traffic and
// poiint it at this proxy, this proxy then relays it onwards upstream,
// parsing its contents and exposing a Prometheus metrics endpoint
// that can be scraped by Prometheus.
//
// This is all because I didn't want to wire up yet another MODBUS
// thingy to my HVAC system.
//
// Disclaimer: this has been tested on exactly one system (mine)
// and reverse engineered by eyeballing the binary traffic. It
// may or may not work for you. (Or for me.)
package main

/*
dnsmasq notes:

dhcp-host=00:90:c2:XX:XX:XX,10.15.25.34,set:usetox
dhcp-option=tag:usetox,option:router,10.15.25.2

Then on fake router (10.15.25.2):

iptables -t nat -I PREROUTING 1 -s 10.15.25.34 -p tcp -m multiport --dports 1030 -j DNAT --to-destination 10.15.25.2:1030

*/

import (
	"context"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	verbose        = flag.Bool("verbose", false, "verbose logging")
	flagListen     = flag.String("listen", ":1030", "listen address for binary protocol")
	flagListenHTTP = flag.String("listen-http", ":1031", "listen address for the prometheus exporter (serving at /metrics)")
)

func main() {
	flag.Parse()
	ln, err := net.Listen("tcp", *flagListen)
	if err != nil {
		log.Fatal(err)
	}
	lnHTTP, err := net.Listen("tcp", *flagListenHTTP)
	if err != nil {
		log.Fatal(err)
	}

	p := &proxy{}

	errc := make(chan error)
	go func() {
		errc <- http.Serve(lnHTTP, p)
	}()
	go func() {
		errc <- p.serveWebsentry(ln)
	}()
	log.Fatal(<-errc)
}

type valAtTime struct {
	v         float64
	t         time.Time
	isCounter bool
}

type proxy struct {
	mu          sync.Mutex
	last        map[propertyID]string
	v           map[string]valAtTime
	keys        []string      // sorted keys of v
	lastSession *proxySession // or nil
}

func (p *proxy) incrMetric(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.v[name]
	p.setMetricLocked(name, m.v+1, true)
	log.Printf("%v = %v", name, m.v+1)
}

func (p *proxy) setMetric(name string, v float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setMetricLocked(name, v, false)
}

func (p *proxy) notePropertyValue(prop propertyID, val string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	was := p.last[prop]
	if was == val {
		// Unchanged.
		return
	}
	if p.last == nil {
		p.last = make(map[propertyID]string)
	}
	p.last[prop] = val
	if n := prop.Name(); n != "" {
		log.Printf("%v (%q) changed %v => %v", prop.StringHex(), n, was, val)
	} else {
		log.Printf("%v changed %v => %v", prop.StringHex(), was, val)
	}
}

func (p *proxy) setMetricLocked(name string, v float64, isCounter bool) {
	_, ok := p.v[name]
	if !ok {
		p.keys = append(p.keys, name)
		sort.Strings(p.keys)
	}
	if p.v == nil {
		p.v = make(map[string]valAtTime)
	}
	p.v[name] = valAtTime{v: v, t: time.Now(), isCounter: isCounter}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/metrics":
		p.serveMetrics(w, r)
	case "/":
		p.serveIndex(w, r)
	case "/last":
		p.serveLast(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *proxy) serveIndex(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, `<html><body><h1>WebSentry MITM Prometheus Exporter</h1>
	<ul>
	<li><a href="/last">/last</a> - last session dump</li>
	<li><a href="/metrics">/metrics</a></li>
</ul>
	`)
}

var startTime = time.Now()

func (p *proxy) serveMetrics(w http.ResponseWriter, req *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "websentry_mitm_uptime %v\n", int64(time.Since(startTime).Seconds()))
	tooOld := time.Now().Add(-5 * time.Minute)
	for _, k := range p.keys {
		m := p.v[k]
		if !m.isCounter && m.t.Before(tooOld) {
			continue
		}
		fmt.Fprintf(w, "%s %.1f\n", k, m.v)
	}
}

func (p *proxy) serveLast(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	s := p.lastSession
	p.mu.Unlock()

	if s == nil {
		http.Error(w, "no last session (yet?)", 404)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Fprintf(w, "<html><body><h1>last session</h1>")
	fmt.Fprintf(w, "<pre>\n")
	for _, f := range s.frames {
		fmt.Fprintf(w, "[%2d]: %s: % 02x\n", f.pktNum, f.sender, f.data[pktHeaderLen:])
	}
	fmt.Fprintf(w, "</pre><h2>props</h2><table>\n")

	var keys []propertyID
	for k := range s.propVal {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, k := range keys {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			k.StringHex(),
			k.Name(),
			html.EscapeString(s.propVal[k]),
		)
	}

	fmt.Fprintf(w, "</table></body></html>\n")
}

func (p *proxy) serveWebsentry(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			log.Printf("unexpected connection type: %T; closing", c)
			c.Close()
			continue
		}
		go p.handleWebsentryConn(tc)
	}
}

const pktHeaderLen = 7

func (p *proxy) handleWebsentryConn(c *net.TCPConn) {
	p.incrMetric("sessions_started")
	defer p.incrMetric("sessions_ended")
	defer c.Close()

	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outc, err := d.DialContext(ctx, "tcp", "websentry.seresco.net:1030")
	if err != nil {
		log.Printf("dial upstream error: %v", err)
		return
	}
	defer outc.Close()

	s := &proxySession{
		p:    p,
		c:    c,
		outc: outc.(*net.TCPConn),
	}
	s.run()

	p.mu.Lock()
	p.lastSession = s
	p.mu.Unlock()
}

type proxySession struct {
	p    *proxy
	c    *net.TCPConn // incoming (from unit)
	outc *net.TCPConn

	mu      sync.Mutex
	pktNum  uint8
	frames  []frame
	propVal map[propertyID]string
}

func (s *proxySession) run() {
	errc := make(chan error, 2)
	go func() {
		errc <- s.copy(senderClient, s.c, s.outc)
	}()
	go func() {
		errc <- s.copy(senderServer, s.outc, s.c)
	}()
	if err := <-errc; err != nil {
		log.Printf("proxy session error: %v", err)
	}
	if err := <-errc; err != nil {
		log.Printf("proxy session error: %v", err)
	}
}

type sender uint8

const (
	senderClient sender = 1
	senderServer sender = 2
)

func (p sender) String() string {
	switch p {
	case senderClient:
		return "C"
	case senderServer:
		return "S"
	default:
		return fmt.Sprintf("party(%d)", p)
	}
}

// frame is a single frame of a packet from either client or server.
type frame struct {
	pktNum uint8  // 1-based, within a session.
	sender sender // "C" or "S"
	data   string // binary; including 7 byte header
}

func parsePropResponse(qf, f frame, onProp func(propertyID, propertyValue)) {
	if qf.sender != senderServer {
		return
	}
	if f.sender != senderClient {
		return
	}
	if qf.data[7] != 0x02 {
		return
	}
	if f.data[7] != 0x02 {
		return
	}

	rem := f.data[8:]
	qrem := qf.data[8:]
	//log.Printf("PARSING\n qrem=% 02x\n  rem=% 02x\n", qrem, rem)

	for len(qrem) >= 3 {
		prop := qrem[:2]
		//log.Printf("Step, prop % 02x:\n qrem=% 02x\n  rem=% 02x\n", prop, qrem, rem)
		if qrem[2] != 0x0f {
			log.Printf("unexpected third byte %02x in server query frame: % 02x", qrem[2], qf.data)
			return
		}
		qrem = qrem[3:]
		if !strings.HasPrefix(rem, prop) {
			log.Printf("didn't find prop % 02x at beginning of % 02x", prop, rem)
			return
		}
		rem = rem[2:]
		val, newRem, err := parsePropValue(rem)
		if err != nil {
			log.Printf("failed to parse prop % 02x value: %v", rem, err)
			return
		}
		//log.Printf("  val=% 02x, newRem=% 02x\n", val.binary, newRem)

		rem = newRem
		onProp(propertyID(uint16(prop[1])|uint16(prop[0])<<8), val)
	}
	if len(qrem) != 0 {
		log.Printf("unexpected trailing bytes in server query frame: % 02x", qrem)
	}
}

func (f frame) isPropertyResponse() bool {
	return f.sender == senderClient && len(f.data) > 7 && f.data[7] == 0x02
}

func (s *proxySession) addFrame(sender sender, b []byte) frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pktNum++
	f := frame{
		pktNum: s.pktNum,
		sender: sender,
		data:   string(b),
	}
	s.frames = append(s.frames, f)

	if f.isPropertyResponse() && len(s.frames) >= 2 {
		qf := s.frames[len(s.frames)-2]
		parsePropResponse(qf, f, func(prop propertyID, val propertyValue) {
			if v, ok := val.Float64(); ok {
				if name := prop.String(); name != "" {
					s.p.setMetric(name, v)
				}
				s.p.setMetric(prop.StringHex(), v)
			}
			valStr := val.String()
			s.p.notePropertyValue(prop, valStr)
			if s.propVal == nil {
				s.propVal = map[propertyID]string{}
			}
			s.propVal[prop] = valStr
		})
	}

	return f
}

func parsePropValue(p string) (val propertyValue, remain string, err error) {
	if len(p) == 0 {
		return val, "", fmt.Errorf("empty property value")
	}
	t := propertyType(p[0])

	// Variable length string.
	if t == 0x07 {
		if len(p) < 2 {
			return val, "", fmt.Errorf("short variable length string")
		}
		n := int(p[1])
		if len(p) < 2+n {
			return val, "", fmt.Errorf("short variable length string")
		}
		return propertyValue{binary: p[:2+n]}, p[2+n:], nil
	}

	var n int
	switch t {
	default:
		return val, "", fmt.Errorf("unknown property type %02x", t)
	case 1, 2:
		n = 1
	case 3, 6, 9:
		n = 2
	case propertyTypeDate, propertyTypeTime, 0x0c:
		n = 4
	case 5:
		n = 4
	case 8:
		n = 7
	}
	if len(p) < 1+n {
		return val, "", fmt.Errorf("short property value")
	}
	return propertyValue{binary: p[:1+n]}, p[1+n:], nil
}

type propertyType byte

const (
	propertyTypeInvalid        propertyType = 0
	propertyTypeVarString      propertyType = 0x07 // variable length string, one length byte, then that many bytes of string
	propertyTypeIP             propertyType = 0x0c // 4 byte IP address
	propertyTypeUint16TimesTen propertyType = 0x06 // value times ten as a uint16
	propertyTypeDate           propertyType = 0x0a // 4 bytes: 7a 06 16 00 = year-1900, month, month_day, always_zero?
	propertyTypeTime           propertyType = 0x0b // 4 bytes: hour, min, something bigger than seconds, zero
	propertyTypeVersion        propertyType = 0x05 // [05 00 05 0f 0c] for version 5.15.12
	// TODO: what are these? only their sizes are known.
	// 0x01: 1 byte (not bool; can be 0x05)
	// 0x02: 1 byte (not bool; can be 00, 01, 02, 03, ...)
	// 0x03: 2 bytes
	// 0x08: 7 bytes (e.g. "00 5a 00 00 00 64 05" or often "00 00 00 00 00 64 05")
	// 0x09: 2 bytes
)

type propertyID uint16

func (p propertyID) String() string {
	if n := p.Name(); n != "" {
		return n
	}
	return p.StringHex()
}

var propName = map[propertyID]string{
	0x1000: "",               // something with date type and value 2011-05-01
	0x0100: "version",        // same as version_string, but in 4 bytes
	0x0101: "version_string", // e.g. "5.15.12"
	0x0103: "serial_number",
	0x0107: "date",
	0x0108: "time",
	0x0402: "ip_address",
	0x0403: "subnet_mask",
	0x0404: "gateway",    // or DNS server? TODO: check which way
	0x0405: "dns_server", // or gateway? TODO: check which way
	0x0600: "humidity_percent",
	0x0601: "room_temp_f",
	0x0602: "supply_air_f",
	0x0603: "outside_air_f",
	0x0604: "pool_temp_f", // I think? Or it's temp in or temp out. But it seems to match the web UI closely.
	0x101d: "",            // some string, value "Off" (blower is currently on, though)
	0x1163: "",            // some time 10:15am
	0x1164: "",            // some time 10:30am
	0x120d: "",            // some string, currently "Ready"
	0x2003: "resolved_websentry_ip",
	// TODO: what is 0x0605? Also water-temp-ish.
	// TODO: what is 0x0606? It's like 165-200-ish (after divide by 10). Compressor temp?
	// TODO: what is 0x0607? Similar to 0606 in range but a bit higher usually. Other header bit?
	// TODO: what is 0x0608? Seems to match pool or air temp, kinda.
	// TODO: what is 0x0609?
	// TODO: what is 0x060a? Often like 16-27 after divide by 10.
	// TODO: what is 0x0610? Seems to match pool or air temp, but higher.
}

func (p propertyID) Name() string {
	return propName[p]
}

func (p propertyID) StringHex() string {
	return fmt.Sprintf("prop_0x%02x%02x", byte(p>>8), byte(p))
}

type propertyValue struct {
	binary string // as binary, starting with the type byte
}

func (v propertyValue) String() string {
	if f, ok := v.Float64(); ok {
		return fmt.Sprint(f)
	}
	switch v.Type() {
	case propertyTypeVarString:
		if len(v.binary) > 2 {
			return fmt.Sprintf("%q", v.binary[2:])
		}
	case propertyTypeIP:
		if len(v.binary) == 5 {
			return fmt.Sprintf("%d.%d.%d.%d", v.binary[1], v.binary[2], v.binary[3], v.binary[4])
		}
	case propertyTypeDate:
		if len(v.binary) == 5 {
			return fmt.Sprintf("%04d-%02d-%02d", int(v.binary[1])+1900, v.binary[2], v.binary[3])
		}
	case propertyTypeTime:
		if len(v.binary) == 5 {
			// [0b 0b 09 78 00] at 11:09am. 0x78 is too big for seconds? Tenths of seconds?
			// TODO: figure out seconds, or what the third byte means.
			return fmt.Sprintf("%02d:%02d [% 02x]", v.binary[1], v.binary[2], v.binary[3:])
		}
	case propertyTypeVersion:
		if len(v.binary) == 5 {
			return fmt.Sprintf("%d.%d.%d.%d", v.binary[1], v.binary[2], v.binary[3], v.binary[4])
		}
	}
	return fmt.Sprintf("[% 02x]", v.binary)
}

func (v propertyValue) Type() propertyType {
	if len(v.binary) == 0 {
		return propertyTypeInvalid
	}
	return propertyType(v.binary[0])
}

func (v propertyValue) Float64() (_ float64, ok bool) {
	switch v.Type() {
	case propertyTypeUint16TimesTen:
		if len(v.binary) == 3 {
			u16 := uint16(v.binary[1])<<8 | uint16(v.binary[2])
			return float64(u16) / 10, true
		}
	}
	return 0, false
}

// copy copies from src to dst, logging each packet.
//
// srcName is either "C" (if src is the client unit) or "S" for the cloud
// server.
func (s *proxySession) copy(sender sender, src, dst *net.TCPConn) error {
	buf := make([]byte, 4<<10)
	defer dst.CloseWrite()
	for {
		_, err := io.ReadFull(src, buf[:pktHeaderLen])
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("%v: header read error: %v", sender, err)
		}

		payLen := int(buf[5])<<8 | int(buf[6])
		if payLen > len(buf)-pktHeaderLen {
			return fmt.Errorf("%v: payload too big: %d", sender, payLen)
		}
		_, err = io.ReadFull(src, buf[pktHeaderLen:][:payLen])
		if err != nil {
			return fmt.Errorf("%v: payload read error: %v", sender, err)
		}
		totalLen := pktHeaderLen + payLen
		f := s.addFrame(sender, buf[:totalLen])
		if *verbose {
			log.Printf("[%2d]: %s: % 02x", f.pktNum, f.sender, f.data[pktHeaderLen:])
		}
		_, err = dst.Write(buf[:totalLen])
		if err != nil {
			return fmt.Errorf("%s: write to peer error: %v", sender, err)
		}
	}
}

/*
Change request from server to client, spectator mode on for one hour:

[ 4]: S: 03 10 1c 03 00 01
[ 5]: C: 03 10 1c 00

   03     # change request
   01 1c  # spectator mode
   03     # duration type in hours?
   00 01  # one hour

Then response is successful ACK ("00")?

*/
