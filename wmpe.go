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
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
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
	v           map[string]valAtTime
	keys        []string      // sorted keys of v
	lastSession *proxySession // or nil
}

func (p *proxy) incrMetric(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.v[name]
	p.setMetricLocked(name, m.v+1, true)

}

func (p *proxy) setMetric(name string, v float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setMetricLocked(name, v, false)
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
	log.Printf("%s now %.1f", name, v)
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
	fmt.Fprintf(w, "</pre>\n</body></html>\n")
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

	mu     sync.Mutex
	pktNum uint8
	frames []frame
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

func parsePropResponse(qf, f frame, onProp func(propID propertyID, val []byte)) {
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

	// TODO: remove this regexp construction. It's a temporary hack to learn
	// the structure of the types and all the types bytes and sizes. Now that
	// those are empirically known, we can write a specific parser for each type
	// and not desperately search for a matching pattern. Also this isn't strictly
	// correct. Unfortunate payload values can mess with the framing. But it was enough
	// for debugging.
	var rxBuf strings.Builder
	rxBuf.WriteString("^")
	qrem := qf.data[8:]
	for len(qrem) > 0 && len(qrem)%3 == 0 {
		if qrem[2] != 0x0f {
			log.Printf("unexpected third byte %02x in server query frame: % 02x", qrem[2], qf.data)
			break
		}
		fmt.Fprintf(&rxBuf, `\b(% 02x)(.+)`, qrem[:2])
		qrem = qrem[3:]
	}
	rxBuf.WriteString("$")

	rx := regexp.MustCompile(rxBuf.String())
	m := rx.FindStringSubmatch(fmt.Sprintf("% 02x", f.data[8:]))
	if m == nil {
		log.Printf("failed to parse pkt %v; match for %q", f.pktNum, rxBuf.String())
		return
	}
	dehex := func(s string) []byte {
		b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
		if err != nil {
			panic(err)
		}
		return b
	}
	for i := 1; i < len(m); i += 2 {
		prop := propertyID(binary.BigEndian.Uint16(dehex(m[i])))
		val := dehex(m[i+1])
		onProp(prop, val)
	}
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

	pay := b[pktHeaderLen:]
	if sender == senderClient && bytes.HasPrefix(pay, []byte{0x02, 0x06, 0, 0x06}) {
		qf := s.frames[len(s.frames)-2]
		_ = qf
		// TODO:	parsePropResponse(qf, f, func(prop propertyID, val []byte) {

		// This is the client sending its key vital temperatures/humidity.
		// 2024/01/05 10:25:37 [ 5]: C: 02 06 00 06 02 08 06 01 06 02 73 06 02 06 02 a5 06 03 06 02 33 06 04 06 02 4c 06 05 06 02 4d 06 06 06 06 ae 06 07 06 06 df 06 08 06 02 3c 06 09 06 03 0e 06 0a 06 00 a8 06 10 06 02 c6
		remain := pay[1:]
		for len(remain) > 0 && len(remain)%5 == 0 {
			chunk := remain[:5] // 2 bytes property ID uint16, 1 byte type (?), 2 bytes uint16
			remain = remain[5:]
			if chunk[2] != 0x06 {
				// type byte? 6 might mean uint16? But empirically it's always 6.
				// Skip if it's not.
				continue
			}
			prop := propertyID(binary.BigEndian.Uint16(chunk[:2]))
			name := prop.String()
			if name != "" {
				val := float64(binary.BigEndian.Uint16(chunk[3:])) / 10
				s.p.setMetric(name, val)
			}
		}
	}

	return f
}

// Type bytes:
// 0x01: 1 byte (not bool; can be 0x05)
// 0x02: 1 byte (not bool; can be 00, 01, 02, 03, ...)
// 0x03: 2 bytes
// 0x05: 5 bytes
// 0x06: 2 byte uint16 (times ten); can be F or percent
// 0x07: variable length string, one length byte, then that many bytes of string
// 0x08: 7 bytes (e.g. "00 5a 00 00 00 64 05" or often "00 00 00 00 00 64 05")
// 0x09: 2 bytes
// 0x0a: 4 bytes
// 0x0b: 4 bytes
// 0x0c: 4 byte IP address

type propertyID uint16

func (p propertyID) String() string {
	switch p {
	case 0x0600:
		return "humidity_percent"
	case 0x0601:
		return "room_temp_f"
	case 0x0602:
		return "supply_air_f"
	case 0x0603:
		return "outside_air_f"
	case 0x0604:
		return "pool_temp_f" // I think? Or it's temp in or temp out. But it seems to match the web UI closely.
	case 0x0101:
		return "version" // e.g. "5.15.12"
	case 0x0103:
		return "serial_number"
	case 0x0402:
		return "ip_address"
	case 0x0403:
		return "subnet_mask"
	case 0x0404:
		return "gateway" // or DNS server? TODO: check which way
	case 0x0405:
		return "dns_server" // or gateway? TODO: check which way
	}
	// TODO: what is 0x0605? Also water-temp-ish.
	// TODO: what is 0x0606? It's like 165-200-ish (after divide by 10). Compressor temp?
	// TODO: what is 0x0607? Similar to 0606 in range but a bit higher usually. Other header bit?
	// TODO: what is 0x0608? Seems to match pool or air temp, kinda.
	// TODO: what is 0x0609?
	// TODO: what is 0x060a? Often like 16-27 after divide by 10.
	// TODO: what is 0x0610? Seems to match pool or air temp, but higher.

	return "" // unknown
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
		log.Printf("[%2d]: %s: % 02x", f.pktNum, f.sender, f.data[pktHeaderLen:])
		_, err = dst.Write(buf[:totalLen])
		if err != nil {
			return fmt.Errorf("%s: write to peer error: %v", sender, err)
		}
	}
}
