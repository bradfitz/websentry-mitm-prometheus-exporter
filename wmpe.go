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

// all fields guarded by (*proxy).mu
type propStats struct {
	prop       propertyID
	last       propertyValue
	lastStr    string    // String of Last
	lastSet    time.Time // last change time
	lastChange time.Time
	queries    int
	changes    int
}

type proxy struct {
	mu          sync.Mutex
	prop        map[propertyID]*propStats
	v           map[string]valAtTime // prometheus metrics
	keys        []string             // sorted keys of v
	lastSession *proxySession        // or nil
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

func (p *proxy) notePropertyValue(prop propertyID, val propertyValue) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	st, ok := p.prop[prop]
	if !ok {
		if p.prop == nil {
			p.prop = map[propertyID]*propStats{}
		}
		st = &propStats{prop: prop}
		p.prop[prop] = st
	}
	st.lastSet = now
	st.queries++
	was := st.last
	if was == val {
		return
	}
	st.last = val
	st.changes++
	st.lastChange = now
	st.lastStr = val.String()

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
	case "/props":
		p.serveProps(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *proxy) serveIndex(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, `<html><body><h1>WebSentry MITM Prometheus Exporter</h1>
	<ul>
	<li><a href="/props">/props</a> - current properties (last seen over all sessions)</li>
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

func (p *proxy) serveProps(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	fmt.Fprintf(w, "<html><body><h1>props</h1><table cellpadding=5 cellspacing=1 border=1>\n")

	var ps []*propStats
	for _, st := range p.prop {
		ps = append(ps, st)
	}
	sort.Slice(ps, func(i, j int) bool {
		return ps[i].prop < ps[j].prop
	})

	for _, st := range ps {

		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%v</td><td>%v</td><td>%s</td><td>%s</td></tr>\n",
			st.prop.StringHex(),
			st.prop.Name(),
			st.queries,
			st.changes,
			html.EscapeString(st.last.DecodedStringOrEmpty()),
			html.EscapeString(st.last.StringHex()),
		)
	}

	fmt.Fprintf(w, "</table></body></html>\n")

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

func (f frame) isChangeRequest() bool {
	return f.sender == senderServer && len(f.data) > 7 && f.data[7] == 0x03
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
			s.p.notePropertyValue(prop, val)
			if s.propVal == nil {
				s.propVal = map[propertyID]string{}
			}
			s.propVal[prop] = val.String()
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
	case 3, 4, 6, 9:
		n = 2
	case propertyTypeDate, propertyTypeTime, 0x0c:
		n = 4
	case 5:
		n = 4
	case 8:
		n = 7
	case propertyTypeUint32:
		n = 4
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
	propertyTypeUint32         propertyType = 0x12 // 4 bytes (for serial numbrer at least)
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
	0x0100: "version",        // same as version_string, but in 4 bytes
	0x0101: "version_string", // e.g. "5.15.12"
	0x0103: "serial_number",
	0x0107: "date",
	0x0108: "time",
	0x010b: "time_zone",            // 0x00 for GMT, 0x06 for PST (GMT, -03:30, AST -4, EST -5, CST -6, MST -7, PST -8, -9, -10)
	0x010e: "temp_unit",            // 0x03 for C, 0x04 for F; affects misc other properties?
	0x0110: "serial_number_string", // 0x0103 but in string form
	0x0116: "",                     // type 3 with val 00 11 (decimal 17, maybe variant: "NE Modbus/LON?")
	0x011a: "set_reboot",           // "S: 03 01 1a 03 00 01" to reboot

	0x0311: "set_event_time_hours",
	0x030d: "set_purge_time_minutes",

	0x0402: "ip_address",
	0x0403: "subnet_mask",
	0x0404: "gateway",    // or DNS server? TODO: check which way
	0x0405: "dns_server", // or gateway? TODO: check which way

	0x0600: "humidity_percent",
	0x0601: "room_temp_f",
	0x0602: "supply_air_f",
	0x0603: "outside_air_f",
	0x0604: "pool_temp_f", // I think? Or it's temp in or temp out. But it seems to match the web UI closely.

	0x1000: "change_filter_date",
	0x1001: "change_filter_months",
	0x101c: "spectator_mode", // I think? 0x00 off, 0x01 on?
	0x101d: "",               // some string, value "Off" (blower is currently on, though)

	0x1122: "sched1_days", //  0 none, 1 all, 2 m-f, 3 sat/sun, 0x04 sun ... 0x0a sat
	0x1123: "sched1_occuped_time_on",
	0x1124: "sched1_occuped_time_off",

	0x1142: "sched2_days", //  0 none, 1 all, 2 m-f, 3 sat/sun, 0x04 sun ... 0x0a sat
	0x1143: "sched2_occuped_time_on",
	0x1144: "sched2_occuped_time_off",

	0x1162: "sched3_days", //  0 none, 1 all, 2 m-f, 3 sat/sun, 0x04 sun ... 0x0a sat
	0x1163: "sched3_occuped_time_on",
	0x1164: "sched3_occuped_time_off",

	0x120d: "blower_state_string", // I think? like "Ready" or "Disabled"
	0x120e: "blower_state",        // 0x00 off, 0x02 on
	0x2003: "resolved_websentry_ip",
	0x2500: "set_room_temp_f",
	0x2501: "set_humidity_percent",
	0x2502: "set_pool_temp_f", // also seems to be a copy in 0x250d?

	0x2503: "set_economizer_min_temp_f", //
	0x2504: "set_freezestat_f",          // alarm if supply air below this for 5 min
	0x2505: "set_purge_shutoff_f",
	0x2506: "set_heat_recovery_f",
	0x250c: "set_disable_ac_at_f",

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

func (v propertyValue) StringHex() string {
	if v.binary == "" {
		return "[empty]"
	}
	return fmt.Sprintf("[% 02x]", v.binary)
}

func (v propertyValue) String() string {
	if s := v.DecodedStringOrEmpty(); s != "" {
		return s
	}
	return v.StringHex()
}

func (v propertyValue) DecodedStringOrEmpty() string {
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
	case propertyTypeUint32:
		if len(v.binary) == 5 {
			return fmt.Sprintf("%d", uint32(v.binary[1])<<24|uint32(v.binary[2])<<16|uint32(v.binary[3])<<8|uint32(v.binary[4]))
		}
	}
	return ""
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
		if *verbose || f.isChangeRequest() {
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
   03     # uint16 type
   00 01  # one hour

Then response is successful ACK ("00")?

Set room temp (0x2500) to 85F: [ 4]: S: 03 25 00 03 00 55  (0x55 is 85)
Set pool temp (0x2502) to 82F: [ 4]: S: 03 25 02 03 00 52  (0x52 is 82)

Set change filters to Jan 9 2024, every 6 months: 2024/01/06 14:36:31 [ 4]: S: 03 10 01 03 00 06 10 00 0a 7c 01 09 00
03
   10 01
      03 uint16 type
	     00 06
   10 00
       0a date type
	     7c 01 09 00  2024-1900/01/09

Change sched 3 days from sat/sun to just sat:

   2024/01/06 14:43:47 [ 4]: S: 03 11 62 03 00 0a
   2024/01/06 14:43:48 prop_0x1162 changed [09 08 03] => [09 08 0a]

   Vals: 0 none, 1 all, 2 m-f, 3 sat/sun, 0x04 sun ... 0x0a sat

Change from PST (-0800 6th entry) to GMT (first):

2024/01/06 14:47:58 [ 4]: S: 03 01 0b 03 00 00
2024/01/06 14:47:58 prop_0x0108 ("time") changed 14:47 [ec 00] => 22:48 [00 00]

From GMT back to PST:

2024/01/06 14:50:05 prop_0x0108 ("time") changed 22:49 [10 00] => 22:50 [18 00]
2024/01/06 14:50:05 [ 4]: S: 03 01 0b 03 00 06
2024/01/06 14:50:05 prop_0x0108 ("time") changed 22:50 [18 00] => 14:50 [1c 00]
2024/01/06 14:50:05 prop_0x010b changed [09 0b 00] => [09 0b 06]

Change from F to C:
2024/01/06 15:07:35 [ 4]: S: 03 01 0e 03 00 03

Change from C to F:

2024/01/06 15:08:39 sessions_started = 4
2024/01/06 15:08:39 prop_0x0108 ("time") changed 15:07 [98 00] => 15:08 [a0 00]
2024/01/06 15:08:39 [ 4]: S: 03 01 0e 03 00 04
2024/01/06 15:08:39 prop_0x0108 ("time") changed 15:08 [a0 00] => 15:08 [a4 00]
2024/01/06 15:08:40 prop_0x2500 ("set_room_temp_f") changed [08 00 1c 00 0c 00 23 01] => [08 00 53 00 37 00 5f 01]
2024/01/06 15:08:40 prop_0x2502 ("set_pool_temp_f") changed [08 00 1b 00 0f 00 2a 01] => [08 00 52 00 3c 00 6c 01]
2024/01/06 15:08:40 prop_0x2503 changed [08 00 20 00 04 00 20 01] => [08 00 5a 00 28 00 5a 01]
2024/01/06 15:08:40 prop_0x2504 changed [08 00 07 ff fa 00 0c 01] => [08 00 2d 00 14 00 37 01]
2024/01/06 15:08:40 prop_0x2505 changed [08 00 12 00 04 00 15 01] => [08 00 41 00 28 00 46 01]
2024/01/06 15:08:40 prop_0x2506 changed [08 00 12 00 04 00 15 01] => [08 00 41 00 28 00 46 01]
2024/01/06 15:08:40 prop_0x2508 changed [08 00 1e 00 01 00 41 01] => [08 00 56 00 23 00 96 01]
2024/01/06 15:08:40 prop_0x250c changed [08 00 15 00 04 00 15 01] => [08 00 46 00 28 00 46 01]
2024/01/06 15:08:41 prop_0x0600 ("humidity_percent") changed 51 => 50.9
2024/01/06 15:08:41 prop_0x0603 ("outside_air_f") changed 55.7 => 55.6
2024/01/06 15:08:41 prop_0x0606 changed 172.7 => 172.9
2024/01/06 15:08:41 prop_0x0607 changed 177.9 => 177.5
2024/01/06 15:08:41 prop_0x0609 changed 78.2 => 78.3
2024/01/06 15:08:41 prop_0x0610 changed 70.8 => 70.7
2024/01/06 15:08:41 prop_0x0e0c changed [03 00 09] => [03 00 04]
2024/01/06 15:08:41 prop_0x1a18 changed [03 00 00] => [03 00 13]
2024/01/06 15:08:42 sessions_ended = 4


set: Disable A/C at 60F

 [ 4]: S: 03 25 0c 03 00 3c


 set freezestat to 44F

 [ 4]: S: 03 25 04 03 00 2c

set Economizer Min Temperature to 89 F

[ 4]: S: 03 25 03 03 00 59

set purge shutoff 55F

[ 4]: S: 03 25 05 03 00 37

set heat recovery to 64F

[ 4]: S: 03 25 06 03 00 40

set event time hours to 2

2024/01/06 18:29:51 [ 4]: S: 03 03 11 03 00 02
2024/01/06 18:29:51 prop_0x0311 changed [08 00 01 00 00 00 18 01] => [08 00 02 00 00 00 18 01]

set purge time 17 minutes

2024/01/06 18:30:55 [ 4]: S: 03 03 0d 03 00 11
2024/01/06 18:30:55 prop_0x0108 ("time") changed 18:30 [e0 00] => 18:30 [e4 00]
2024/01/06 18:30:55 prop_0x030d changed [08 00 0f 00 00 00 3c 05] => [08 00 11 00 00 00 3c 05]

Stop blower:

2024/01/06 18:33:00 [ 4]: S: 03 0c 01 03 00 00
2024/01/06 18:33:00 prop_0x120d changed "Ready" => "Disabled"
2024/01/06 18:33:00 prop_0x120e changed [02 02] => [02 00]
2024/01/06 18:33:00 prop_0x0c01 changed [09 01 01] => [09 01 00]

Start blower:

2024/01/06 18:34:04 [ 4]: S: 03 0c 01 03 00 01
2024/01/06 18:34:04 prop_0x0c01 changed [09 01 00] => [09 01 01]
....
2024/01/06 18:35:08 prop_0x120e changed [02 00] => [02 02]
...
2024/01/06 18:52:38 prop_0x120d changed "Disabled" => "Ready"  (when I sent another command later; probably didn't take this long)

turn on spectator mode for 1 hour:

2024/01/06 18:52:37 prop_0x0108 ("time") changed 18:51 [94 00] => 18:52 [9c 00]
2024/01/06 18:52:38 [ 4]: S: 03 03 11 03 00 01 10 1c 03 00 01
2024/01/06 18:52:38 prop_0x0311 changed [08 00 02 00 00 00 18 01] => [08 00 01 00 00 00 18 01]

03
   03 11
      03
       00 01
   10 1c
      03
       00 01

System restart:

18:56:47 [ 4]: S: 03 01 1a 03 00 01
2024/01/06 18:56:47 prop_0x120d changed "Ready" => "Disabled"
2024/01/06 18:56:47 prop_0x120e changed [02 02] => [02 00]


*/
