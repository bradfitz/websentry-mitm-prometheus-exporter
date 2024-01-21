// The websentry-mitm-prometheus-exporter is a MITM proxy server for the
// WebSentry port 1030 protocol between WebSentry-capable dehumidifiers (see
// https://dehumidifiedairsolutions.com/) and its cloud service (TCP
// websentry.seresco.net:1030).
//
// Assuming you set up fake DNS entries or DHCP + iptables to intercept the
// traffic and point it at this proxy, this proxy then relays it onwards
// upstream, parsing its contents and exposing a Prometheus metrics endpoint
// that can be scraped by Prometheus.
//
// This is all because I didn't want to wire up yet another MODBUS thingy to my
// HVAC system.
//
// Disclaimer: this has been tested on exactly one system (mine) and reverse
// engineered by eyeballing the binary traffic. It may or may not work for you.
// (Or for me.)
//
// For protocol details, see https://github.com/bradfitz/websentry-mitm-prometheus-exporter/blob/main/websentry-protocol.md
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
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sigurn/crc16"
)

var (
	verbose        = flag.Bool("verbose", false, "verbose logging")
	flagListen     = flag.String("listen", ":1030", "listen address for binary protocol")
	flagListenHTTP = flag.String("listen-http", ":1031", "listen address for the prometheus exporter (serving at /metrics)")
	flagRawLogFile = flag.String("raw-log", "", "if non-empty, path to append raw protocol logs to, in JSON form")
	flagDecode     = flag.Bool("decode", false, "decode the --raw-log file but don't run a server")
)

func main() {
	flag.Parse()
	if *flagDecode {
		if *flagRawLogFile == "" {
			log.Fatal("--decode requires --raw-log")
		}
		if err := decodeFile(*flagRawLogFile); err != nil {
			log.Fatal(err)
		}
		return
	}

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

	wantMD := r.FormValue("format") == "md"

	if wantMD {
		fmt.Fprintf(w, `| Code | Name | Type | Sample Value | Sample, Decoded | 
| -----| ---- | ---- | ------------ | --------------- | 
`)
	} else {
		fmt.Fprintf(w, "<html><body><h1>props</h1><table cellpadding=5 cellspacing=1 border=1>\n")
	}

	var ps []*propStats
	for _, st := range p.prop {
		ps = append(ps, st)
	}
	sort.Slice(ps, func(i, j int) bool {
		return ps[i].prop < ps[j].prop
	})

	for _, st := range ps {
		if wantMD {
			last := strings.Trim(st.last.StringHex(), "[]")
			sampleVal := last[3:]
			sampleDecoded := st.last.DecodedStringOrEmpty()

			if m, ok := properties[st.prop]; ok {
				if m.Sample != "" {
					sampleVal = m.Sample
				}
				if m.Decoded != "" {
					sampleDecoded = m.Decoded
				}
			}

			fields := []string{
				strings.TrimPrefix(st.prop.StringHex(), "prop_"),
				st.prop.Name(),
				"`0x" + fmt.Sprintf(last[:2]) + "`",
				"<nobr>`" + sampleVal + "`</nobr>",
				sampleDecoded,
			}
			fmt.Fprintf(w, "| %s |\n", strings.Join(fields, " | "))
			continue
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%v</td><td>%v</td><td>%s</td><td>%s</td></tr>\n",
			st.prop.StringHex(),
			st.prop.Name(),
			st.queries,
			st.changes,
			html.EscapeString(st.last.DecodedStringOrEmpty()),
			html.EscapeString(st.last.StringHex()),
		)
	}

	if !wantMD {
		fmt.Fprintf(w, "</table></body></html>\n")
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

	for _, f := range s.frames {
		if !f.isPropertyRequest() {
			continue
		}
		f.foreachPropertyRequest(func(k propertyID) {
			fmt.Fprintf(w, "<tr><td>%d/%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				f.pktNum, f.pktNum+1,
				k.StringHex(),
				k.Name(),
				html.EscapeString(s.propVal[k].DecodedStringOrEmpty()),
				html.EscapeString(s.propVal[k].StringHex()),
			)
		})
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
		start: time.Now(),
		p:     p,
		c:     c,
		outc:  outc.(*net.TCPConn),
	}
	s.run()
	s.durSec = time.Since(s.start).Seconds()

	p.mu.Lock()
	p.lastSession = s
	p.mu.Unlock()

	p.writeRawLog(s)
}

type sessionJSON struct {
	Start  time.Time
	DurSec float64
	Frames []frameJSON
}

type frameJSON struct {
	N int    `json:",omitempty"`
	C []byte `json:",omitempty"`
	S []byte `json:",omitempty"`
}

func (p *proxy) writeRawLog(s *proxySession) {
	if *flagRawLogFile == "" {
		return
	}

	js := sessionJSON{
		Start:  s.start,
		DurSec: s.durSec,
	}
	for _, f := range s.frames {
		jf := frameJSON{N: int(f.pktNum)}
		if f.sender == senderClient {
			jf.C = []byte(f.data)
		} else if f.sender == senderServer {
			jf.S = []byte(f.data)
		}
		js.Frames = append(js.Frames, jf)
	}

	jb, err := json.MarshalIndent(js, "", "\t")
	if err != nil {
		log.Printf("failed to marshal raw log: %v", err)
		return
	}
	jb = append(jb, '\n')

	p.mu.Lock()
	defer p.mu.Unlock()

	f, err := os.OpenFile(*flagRawLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to open raw log file %q: %v", *flagRawLogFile, err)
		return
	}
	if _, err := f.Write(jb); err != nil {
		f.Close()
		log.Printf("failed to write raw log file %q: %v", *flagRawLogFile, err)
		return
	}
	if err := f.Close(); err != nil {
		log.Printf("failed to close raw log file %q: %v", *flagRawLogFile, err)
		return
	}
}

type proxySession struct {
	p    *proxy
	c    *net.TCPConn // incoming (from unit)
	outc *net.TCPConn

	start  time.Time
	durSec float64

	mu      sync.Mutex
	pktNum  uint8
	frames  []frame
	propVal map[propertyID]propertyValue
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

func parsePropResponse(qf, f frame, onProp func(propertyValue)) {
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
		id := propertyID(uint16(prop[1]) | uint16(prop[0])<<8)
		val, newRem, err := parsePropValue(id, rem)
		if err != nil {
			log.Printf("failed to parse prop % 02x value: %v", rem, err)
			return
		}
		//log.Printf("  val=% 02x, newRem=% 02x\n", val.binary, newRem)
		rem = newRem
		onProp(val)
	}
	if len(qrem) != 0 {
		log.Printf("unexpected trailing bytes in server query frame: % 02x", qrem)
	}
}

func (f frame) isPropertyResponse() bool {
	return f.sender == senderClient && len(f.data) > 7 && f.data[7] == 0x02
}

func (f frame) isPropertyRequest() bool {
	return f.sender == senderServer && len(f.data) > 7 && f.data[7] == 0x02
}

func (f frame) isChangeRequest() bool {
	return f.sender == senderServer && len(f.data) > 7 && f.data[7] == 0x03
}

func (f frame) isClientInit() bool {
	return f.sender == senderClient && len(f.data) > 7 && f.data[7] == 0x00
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
		parsePropResponse(qf, f, func(val propertyValue) {
			prop := val.id
			if v, ok := val.Float64(); ok {
				if name := prop.String(); name != "" {
					s.p.setMetric(name, v)
				} else {
					s.p.setMetric(prop.StringHex(), v)
				}
			}
			s.p.notePropertyValue(prop, val)
			if s.propVal == nil {
				s.propVal = map[propertyID]propertyValue{}
			}
			s.propVal[prop] = val
		})
	}

	return f
}

func (f frame) foreachPropertyRequest(fn func(propertyID)) {
	if !f.isPropertyRequest() {
		return
	}
	rem := f.data[8:] // guaranteed at least this size by isPropertyRequest
	for len(rem) >= 3 && rem[2] == 0x0f {
		id := uint16(rem[0])<<8 | uint16(rem[1])
		fn(propertyID(id))
		rem = rem[3:]
	}
}

func parsePropValue(id propertyID, p string) (val propertyValue, remain string, err error) {
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
		return propertyValue{id, p[:2+n]}, p[2+n:], nil
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
	case propertyUint16InRange:
		n = 7
	case propertyTypeUint32:
		n = 4
	}
	if len(p) < 1+n {
		return val, "", fmt.Errorf("short property value")
	}
	return propertyValue{id, p[:1+n]}, p[1+n:], nil
}

type propertyType byte

const (
	propertyTypeInvalid        propertyType = 0
	propertyTypeVarString      propertyType = 0x07 // variable length string, one length byte, then that many bytes of string
	propertyTypeIP             propertyType = 0x0c // 4 byte IP address
	propertyTypeUint16TimesTen propertyType = 0x06 // value times ten as a uint16
	propertyTypeDate           propertyType = 0x0a // 4 bytes: 7a 06 16 00 = year-1900, month, month_day, always_zero?
	propertyTypeTime           propertyType = 0x0b // 4 bytes: hour, min, (seconds<<2), zero
	propertyTypeVersion        propertyType = 0x05 // [05 00 05 0f 0c] for version 5.15.12
	propertyTypeUint32         propertyType = 0x12 // 4 bytes (for serial numbrer at least)
	propertyUint16InRange      propertyType = 0x08 // 7 bytes: 3 uint16s: current, min acceptable, max acceptable + 1 byte granularity? if current == 0 and less than min, unset/not applicable.
	// TODO: what are these? only their sizes are known.
	// 0x01: 1 byte (not bool; can be 0x05)
	// 0x02: 1 byte (not bool; can be 00, 01, 02, 03, ...)
	// 0x03: 2 bytes // enum maybe where first byte is the enum type?
	// 0x09: 2 bytes
)

type propertyID uint16

func (p propertyID) String() string {
	if n := p.Name(); n != "" {
		return n
	}
	return p.StringHex()
}

type propertyMeta struct {
	Name    string // TODO: not yet used or dup checked; should merge propNames map into properties
	Sample  string // "00 05 0f 0c" (without type byte)
	Decoded string
	Enum    map[byte]string
}

// enum type 0x08 (e.g. [09 08 01] for all days)
var enumDays = map[byte]string{
	0:  "none",
	1:  "all-days",
	2:  "mon-fri",
	3:  "sat-sun",
	4:  "sun",
	5:  "mon",
	6:  "tue",
	7:  "wed",
	8:  "thu",
	9:  "fri",
	10: "sat",
}

var properties = map[propertyID]*propertyMeta{
	0x010b: {
		Decoded: "0x00 for GMT, 0x06 for PST (GMT, -03:30, AST -4, EST -5, CST -6, MST -7, PST -8, -9, -10)",
		Enum: map[byte]string{ // enum type 0x0b
			0x00: "GMT",
			0x01: "-03:30",
			0x02: "AST",
			0x03: "EST",
			0x04: "CST",
			0x05: "MST",
			0x06: "PST",
			0x07: "-09:00",
			0x08: "-10:00",
		},
	},
	0x010e: {
		Decoded: "0x03 for C, 0x04 for F; affects misc other properties?",
		Enum: map[byte]string{ // enum type 0x2d
			0x03: "Celsius",
			0x04: "Fahrenheit",
		},
	},
	0x1122: {
		Decoded: "0=none, 1=all, 2=m-f, 3=sat/sun, 4=sun, 5=mon, ..., 0x0a=sat",
		Enum:    enumDays,
	},
	0x1142: {
		Decoded: "0=none, 1=all, 2=m-f, 3=sat/sun, 4=sun, 5=mon, ..., 0x0a=sat",
		Enum:    enumDays,
	},
	0x1162: {
		Decoded: "0=none, 1=all, 2=m-f, 3=sat/sun, 4=sun, 5=mon, ..., 0x0a=sat",
		Enum:    enumDays,
	},
	0x0103: {
		Sample:  "07 5b cd 15",
		Decoded: "123456789",
	},
	0x0110: {
		Sample:  "09 31 32 33 34 35 36 37 38 39",
		Decoded: `"123456789"`,
	},
	0x2300: {
		Name: "lon_enabled",
		Enum: map[byte]string{ // enum type 0x2c
			0: "off",
			1: "read/write",
			2: "read-only",
		},
	},
	0x190a: {
		Name: "dehumidifer_state",
		Enum: map[byte]string{
			0: "Disabled",
			1: "Idle",
			2: "Dehumidifying",
			3: "Pending",
		},
	},
	0x100f: {
		Name: "ventilation_state",
		Enum: map[byte]string{
			0:  "Stopped",
			1:  "Stabilize",
			2:  "Day Time",
			3:  "Night Time",
			4:  "Stopping",
			5:  "Shutting Down",
			6:  "Pending Purge",
			7:  "Purge",
			8:  "Economizer",
			9:  "Slave Mode",
			10: "Freezestat",
			11: "PendEcono",
			12: "Spectators",
		},
	},
	0x0111: {
		Name: "system_mode",
		Enum: map[byte]string{
			0: "Startup",
			1: "Normal",
			2: "Service",
			3: "Shut Down",
			4: "Restart",
			5: "Off",
			6: "Night Time",
			7: "Day Time",
			8: "Event 1",
			9: "Event 2",
		},
	},
	0x0e02: {
		Name: "supply_air_mode",
		Enum: map[byte]string{
			0: "Disabled",
			2: "Cool",
			1: "Idle",
			3: "Heat",
			4: "Hold",
			5: "HoldCool",
			6: "HoldHeat",
		},
	},
	0x120e: {
		Name: "blower_state",
		Enum: map[byte]string{
			0:  "Disabled",
			1:  "No Ventilation",
			2:  "Ready",
			3:  "Starting up",
			4:  "Stabilize",
			5:  "Min Runtime",
			6:  "Stable",
			7:  "Stopping",
			9:  "Min Stop Time",
			12: "Shutting Down",
			14: "External Off",
			15: "Pump Fault",
		},
	},
	0x1a04: {
		Name: "room_temp_state",
		Enum: map[byte]string{
			0: "Disabled",
			1: "Idle",
			2: "Lower",
			3: "Higher",
			4: "Partial Cooling",
			5: "Partial Heating",
			6: "Econo Cooling",
		},
	},
	// 0x1220: some percent that goes between 0 and 100 when rebooting?

	0x0c03: {
		Name: "TODO_some_state",
		Enum: map[byte]string{
			0: "Power Up",
			1: "Stopped",
			2: "Running",
			3: "Stopping",
			4: "Pending Start",
			5: "Stabilize",
			6: "Alarm",
		},
	},

	0x1612: {
		Name: "pool_heating_state_maybe", // I think
		Enum: map[byte]string{
			0: "Off",
			1: "Heating",
			// ...
		},
	},

	0x0102: {
		Name: "board_version",
		Enum: map[byte]string{ // enum type 0x1b (27)
			16: "7.0",
			17: "7.1",
			18: "7.2",
			19: "8.0",
			20: "8.1",
			21: "9.0",
		},
	},
}

func init() {
	for id, dm := range properties {
		if dm.Name == "" {
			continue
		}
		was, ok := propName[id]
		if !ok {
			propName[id] = dm.Name
			continue
		}
		if was == dm.Name {
			continue
		}
		panic(fmt.Sprintf("name defined two ways: %q and %q", was, dm.Name))
	}
}

// TODO: merge this into properties above.
var propName = map[propertyID]string{
	0x0100: "version",        // same as version_string, but in 4 bytes
	0x0101: "version_string", // e.g. "5.15.12"
	0x0103: "serial_number",
	0x0107: "date",
	0x0108: "time",
	0x010b: "time_zone",            // 0x00 for GMT, 0x06 for PST (GMT, -03:30, AST -4, EST -5, CST -6, MST -7, PST -8, -9, -10)
	0x010e: "temp_unit",            // 0x03 for C, 0x04 for F; affects misc other properties?
	0x0110: "serial_number_string", // 0x0103 but in string form
	0x0116: "software_variant",     // type 3 with val 00 11 (decimal 17, maybe variant: "NE Modbus/LON?")
	0x011a: "set_reboot",           // "S: 03 01 1a 03 00 01" to reboot

	0x0311: "set_event_time_hours",
	0x030d: "set_purge_time_minutes",

	0x0402: "ip_address",
	0x0403: "subnet_mask",
	0x0404: "gateway",
	0x0405: "dns_server",

	0x0600: "humidity_percent",
	0x0601: "room_temp_f",
	0x0602: "supply_air_f",
	0x0603: "outside_air_f",
	0x0604: "pool_temp_f",     // inlet (from pool to unit)
	0x0605: "pool_temp_out_f", // outlet (usually bit warmer than inlet)
	0x0606: "high_pressure_psi",
	0x0607: "low_pressure_psi",
	0x0608: "evaporator_temp_f",
	0x0609: "suction_temp_f",
	0x0610: "discharge_temp_f",
	0x060a: "superheat_temp_f",

	0x0701: "blower_speed_percent", // I think. It's the only value that's 90 (matching UI) in range 0-100: [08 00 5a 00 00 00 64 05]

	0x1000: "change_filter_date",
	0x1001: "change_filter_months",

	// Advanced > Ventillation > Exhaust Fans
	0x1016: "exhaust_fan_unoccupied_percent",
	0x1017: "exhaust_fan_occupied_percent",
	0x1018: "fan1_capacity_percent",
	0x101b: "spectator_fan_percent",
	0x1004: "exhaust_fan_stop_on_overload",

	// Advanced > Ventillation > Main Blower
	0x0c04: "blower_normal_speed_percent",
	0x0c05: "blower_secondary_speed_percent",

	// Advanced > Ventillation > Ventillation Options
	0x010f: "fire_alarm_reset", // 0x03 then second byte 0=auto, 1=manual

	// Network > WebSentry
	0x0333: "websentry_connect_interval_sec",

	// Network >> TCP/IP
	0x0400: "dhcp_enabled",
	0x0300: "start_network_device_sec",
	0x0303: "reboot_device_min",
	0x0304: "reboot_delay_sec",

	// Network >> LON
	0x2300: "lon_enabled", // 0=off, 1=read/write, 2=read-only

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

	// Advanced > Control Status ("internal params" docs say)
	0x1a18: "adv_control_status_internal_room_heat",
	0x0e0c: "adv_control_status_internal_heat_on",

	0x1207: "set_high_pressure_psi",
	0x120d: "blower_state_string", // I think? like "Ready" or "Disabled"
	0x1214: "set_low_pressure_psi",
	0x122c: "oacc_min_hp_change_psi", // I think? Only 5 (1-50) set.

	0x2003: "resolved_websentry_ip",
	0x2500: "set_room_temp_f",
	0x2501: "set_humidity_percent",
	0x2502: "set_pool_temp_f", // also seems to be a copy in 0x250d?

	0x2201: "set_modbus_enabled", //  off-on: S: 03(set) 22 01 03(type) 00 01

	0x2503: "set_economizer_min_temp_f", //
	0x2504: "set_freezestat_f",          // alarm if supply air below this for 5 min
	0x2505: "set_purge_shutoff_f",
	0x2506: "set_heat_recovery_f",
	0x2508: "set_supply_air_f", // I think. It's the only value set to 84 and matches https://photos.google.com/photo/AF1QipMsMLz4YwAK1Q4VTIIqcn92ggfPIKOTrQBL95lh
	0x250c: "set_disable_ac_at_f",

	// TODO: super heat setting. (several things are currently 15; toggle on TouchPanel to see what changes)
}

func (p propertyID) Name() string {
	return propName[p]
}

func (p propertyID) StringHex() string {
	return fmt.Sprintf("prop_0x%02x%02x", byte(p>>8), byte(p))
}

type propertyValue struct {
	id     propertyID
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
			return fmt.Sprintf("%02d:%02d:%02d", v.binary[1], v.binary[2], v.binary[3]>>2)
		}
	case propertyTypeVersion:
		if len(v.binary) == 5 {
			return fmt.Sprintf("%d.%d.%d.%d", v.binary[1], v.binary[2], v.binary[3], v.binary[4])
		}
	case propertyTypeUint32:
		if len(v.binary) == 5 {
			return fmt.Sprintf("%d", uint32(v.binary[1])<<24|uint32(v.binary[2])<<16|uint32(v.binary[3])<<8|uint32(v.binary[4]))
		}
	case propertyUint16InRange:
		if len(v.binary) != 8 {
			return "invalid-uint16-in-range"
		}
		cur, lo, hi := uint16(v.binary[1])<<8|uint16(v.binary[2]), uint16(v.binary[3])<<8|uint16(v.binary[4]), uint16(v.binary[5])<<8|uint16(v.binary[6])
		step := uint16(v.binary[7])
		if cur == 0 && lo != 0 {
			return fmt.Sprintf("- (%d-%d by %d)", lo, hi, step)
		}
		// TODO: add unit based on property ID.
		return fmt.Sprintf("%d (%d-%d by %d)", cur, lo, hi, step)
	case 2: // enum value that's property-specific without a type?
		if len(v.binary) == 2 {
			if pm, ok := properties[v.id]; ok {
				if s, ok := pm.Enum[v.binary[1]]; ok {
					return s
				}
			}
		}
	case 9: // enum value?
		if len(v.binary) == 3 {
			if pm, ok := properties[v.id]; ok {
				if s, ok := pm.Enum[v.binary[2]]; ok {
					return s
				}
			}
			switch v.binary[1] { // enum type byte?
			case 0:
				switch v.binary[2] {
				case 0:
					return "No"
				case 1:
					return "Yes"
				}
			case 1, 46:
				switch v.binary[2] {
				case 0:
					return "Off"
				case 1:
					return "On"
				case 2:
					return "N/A" // type 46 only
				}
			case 2:
				switch v.binary[2] {
				case 0:
					return "Disabled"
				case 1:
					return "Enabled"
				}
			case 3:
				switch v.binary[2] {
				case 0:
					return "Auto"
				case 1:
					return "Manual"
				}
			case 50:
				switch v.binary[2] {
				case 0:
					return "Open"
				case 1:
					return "Closed"
				}
			}
			return fmt.Sprintf("%d(et=%d)", v.binary[2], v.binary[1])
		}
	}

	if f, ok := v.Float64(); ok {
		if v.id == 0x0116 { // software variant?
			switch f {
			case 17:
				return "NE Modbus/LON" // Only unit I have, so I'm guessing it's this string to match the web values.
			}
		}
		return fmt.Sprint(f)
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
	case propertyUint16InRange:
		if len(v.binary) == 8 {
			return float64(uint16(v.binary[1])<<8 | uint16(v.binary[2])), true
		}
	case 3:
		if len(v.binary) == 3 {
			return float64(uint16(v.binary[1])<<8 | uint16(v.binary[2])), true
		}
	case 9: // enum; first byte is enum type, second byte is uint8 value.
		if len(v.binary) == 3 {
			return float64(v.binary[2]), true
		}

	case 2:
		if len(v.binary) == 2 {
			return float64(v.binary[1]), true
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

func decodeFile(fname string) error {
	f, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer f.Close()
	jd := json.NewDecoder(f)

	p := new(proxy)

	// series of property changes, each with a query and response.
	type valAndTime struct {
		v propertyValue
		t time.Time
	}
	hist := map[propertyID][]valAndTime{}

	for {
		var s sessionJSON
		err := jd.Decode(&s)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		fmt.Printf("## Time: %v\n", s.Start)

		ps := &proxySession{p: p}

		for _, f := range s.Frames {
			if f.N == 1 {
				fmt.Printf("  % 02x\n", f.C)
				continue
			}
			if f.C != nil {
				ps.addFrame(senderClient, f.C)
			}
			if f.S != nil {
				ps.addFrame(senderServer, f.S)
			}
		}

		for p := range ps.propVal {
			if p.Name() != "" {
				continue
			}
			hist[p] = append(hist[p], valAndTime{v: ps.propVal[p], t: s.Start})
		}
	}

	return nil
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


# decoding time type's 3rd byte, some stats...

first nibble of third byte, never starts with 0xf

[root@tox:~]# less proxy.log  | grep time | perl -ne 'm,\[(.), and print $1 . "\n"' | sort |uniq -c | sort -k 2
     46 0
     40 1
     47 2
     50 3
     40 4
     50 5
     46 6
     45 7
     46 8
     46 9
     49 a
     52 b
     44 c
     50 d
     50 e

 second nibble of 3rd byte:

[root@tox:~]# less proxy.log  | grep time | perl -ne 'm,\[.(.), and print $1 . "\n"' | sort |uniq -c | sort -k 2 | less
    168 0
    185 4
    166 8
    179 c


Top changing properties after ~1441 minutes heating:

      2 0x2303
      3 0x0107 ("date")
    112 0x060a
    327 0x0605
    330 0x0604 ("pool_temp_f")
    574 0x0601 ("room_temp_f")
    612 0x0608
    704 0x0609
    738 0x0603 ("outside_air_f")
    798 0x0610
    910 0x0602 ("supply_air_f")
    918 0x0600 ("humidity_percent")
   1260 0x0607
   1292 0x0606
   1318 0x1a18
   1363 0x0e0c
   1441 0x0108 ("time")

# Looking for the state/mode bits.

Maybe:

2024/01/18 09:49:27 prop_0x0e0c changed 0 => 6
2024/01/18 09:49:27 prop_0x1a18 changed 15 => 12

"Seresco LON Virtual Objects" doc has some clues but haven't found it.

 // Advanced > Control Status ("internal params" docs say)
// prop_0x1a18 is room heat number like 19 or 3 or 0 or 24 etc
// prop_0x0e0c is heat on. 0 or 1 or 5 or 10

// Advanced > Ventillation > Exhaust Fans
// Fan 1 capacity %: prop_0x1018 changed 99 (5-100 by 1) => 98 (5-100 by 1)
// Exhaust Fan, Occupied (%) prop_0x1017 changed 99 (1-100 by 1) => 97 (1-100 by 1)
// Exhaust Fan, Unoccupied (%) prop_0x1016 changed 0 (0-100 by 1) => 6 (0-100 by 1)
// Spectators (%): 99 to 100 prop_0x101b changed 99 (1-200 by 1) => 100 (1-200 by 1)
// Stop on overload: no=>yes prop_0x1004 changed [09 00 00] => [09 00 01]

// Advanced > Ventillation > Main Blower
// Normal speed %: prop_0x0c04 changed 90 (10-100 by 5) => 89 (10-100 by 5)
// Secondary Speed %: prop_0x0c05 changed 60 (10-100 by 5) => 61 (10-100 by 5)

// > Ven Opts
// Fire Alarm Reset: manual to auto: prop_0x010f changed [09 03 01] => [09 03 00]

// WebSentry communication interval sec:
// prop_0x0333 changed 60 (5-600 by 5) => 15 (5-600 by 5)

// Advanced > Network > TCP/IP:
// DHCP yes to no: prop_0x0400 changed [09 00 01] => [09 00 00]
// Start network device (sec): prop_0x0300 changed 120 (1-600 by 5) => 60 (1-600 by 5)
// Reboot device (minutes): prop_0x0303 changed 60 (1-600 by 10) => 61 (1-600 by 10)
// Reboot delay (sec): prop_0x0304 changed 10 (1-60 by 1) => 11 (1-60 by 1)

// LON enabled: off to readonly:  prop_0x2300 changed [09 2c 00] => [09 2c 02] (1 is read/write))

## After a restart:

Jan 20 10:40:04 tox websentry-proxy-start[7119]: 2024/01/20 10:40:04 sessions_started = 10
Jan 20 10:40:05 tox websentry-proxy-start[7119]: 2024/01/20 10:40:05 prop_0x1220 changed 100 => 0
Jan 20 10:40:05 tox websentry-proxy-start[7119]: 2024/01/20 10:40:05 prop_0x0108 ("time") changed 10:39:54 => 10:40:04
Jan 20 10:40:05 tox websentry-proxy-start[7119]: 2024/01/20 10:40:05 prop_0x0600 ("humidity_percent") changed 54.9 => 54.8
Jan 20 10:40:05 tox websentry-proxy-start[7119]: 2024/01/20 10:40:05 prop_0x0604 ("pool_temp_f") changed 66.7 => 66.6
Jan 20 10:40:05 tox websentry-proxy-start[7119]: 2024/01/20 10:40:05 prop_0x0606 ("high_pressure_psi") changed 192.7 => 191.8
Jan 20 10:40:05 tox websentry-proxy-start[7119]: 2024/01/20 10:40:05 prop_0x0607 ("low_pressure_psi") changed 197.7 => 197.4
Jan 20 10:40:05 tox websentry-proxy-start[7119]: 2024/01/20 10:40:05 prop_0x0608 ("evaporator_temp_f") changed 64.6 => 64.7
Jan 20 10:40:05 tox websentry-proxy-start[7119]: 2024/01/20 10:40:05 prop_0x060a ("superheat_temp_f") changed 13.2 => 13.4
Jan 20 10:40:05 tox websentry-proxy-start[7119]: 2024/01/20 10:40:05 prop_0x091e changed false(et=1) => true(et=1)
Jan 20 10:40:05 tox websentry-proxy-start[7119]: 2024/01/20 10:40:05 prop_0x0e0c ("adv_control_status_internal_heat_on") changed 4 => 0
Jan 20 10:40:05 tox websentry-proxy-start[7119]: 2024/01/20 10:40:05 prop_0x1227 changed 2 => 0
Jan 20 10:40:05 tox websentry-proxy-start[7119]: 2024/01/20 10:40:05 prop_0x1a18 ("adv_control_status_internal_room_heat") changed 6 => 0
Jan 20 10:40:06 tox websentry-proxy-start[7119]: 2024/01/20 10:40:06 sessions_ended = 10

Jan 20 10:43am approximately, transitioned from "heating mode" (room) on to off to on

The client init final byte might be a bitmask of state? normally 0x07, changes to 0x04 for a bit, then bottom two bits are set again.

  70 83 9e e8 e6 00 12 00 ff 00 02 05 04 01 0d 00 90 c2 0c 02 b3 01 20 02 07
## Time: 2024-01-20 10:39:54.264483473 -0800 PST
  70 83 9e e8 e6 00 12 00 ff 00 02 05 04 01 0d 00 90 c2 0c 02 b3 01 20 02 07
## Time: 2024-01-20 10:40:05.147378131 -0800 PST
  70 83 9e e9 a6 00 12 00 ff 00 02 05 04 01 0d 00 90 c2 0c 02 b3 01 20 02 04
## Time: 2024-01-20 10:40:21.761667561 -0800 PST
  70 83 9e e9 a6 00 12 00 ff 00 02 05 04 01 0d 00 90 c2 0c 02 b3 01 20 02 04
## Time: 2024-01-20 10:40:38.453582792 -0800 PST
  70 83 9e e9 a6 00 12 00 ff 00 02 05 04 01 0d 00 90 c2 0c 02 b3 01 20 02 04
## Time: 2024-01-20 10:40:55.074033806 -0800 PST
  70 83 9e e9 a6 00 12 00 ff 00 02 05 04 01 0d 00 90 c2 0c 02 b3 01 20 02 04
## Time: 2024-01-20 10:41:11.737971174 -0800 PST
  70 83 9e e8 e6 00 12 00 ff 00 02 05 04 01 0d 00 90 c2 0c 02 b3 01 20 02 07
## Time: 2024-01-20 10:41:28.424343832 -0800 PST
  70 83 9e e8 e6 00 12 00 ff 00 02 05 04 01 0d 00 90 c2 0c 02 b3 01 20 02 07

## After another restart,

A "stabilize" in here?

Jan 20 11:35:43 tox websentry-proxy-start[7184]: 2024/01/20 11:35:43 sessions_started = 149
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x0108 ("time") changed 11:35:26 => 11:35:43
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x0603 ("outside_air_f") changed 64.2 => 64.4
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x0606 ("high_pressure_psi") changed 192.2 => 192.3
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x0607 ("low_pressure_psi") changed 197.5 => 198
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x0610 ("discharge_temp_f") changed 76.8 => 76.9
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x0701 ("blower_speed_percent") changed 0 (0-100 by 5) => 90 (0-100 by 5)
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x0900 changed false(et=1) => true(et=1)
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x090e changed false(et=1) => true(et=1)
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x0111 changed 0 => 1
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x012b changed false(et=1) => true(et=1)
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x0c03 changed 1 => 2
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x100f changed 0 => 1
Jan 20 11:35:44 tox websentry-proxy-start[7184]: 2024/01/20 11:35:44 prop_0x1b2b changed 0 => 3
Jan 20 11:35:45 tox websentry-proxy-start[7184]: 2024/01/20 11:35:45 sessions_ended = 149


Jan 20 11:36:00 tox websentry-proxy-start[7184]: 2024/01/20 11:36:00 sessions_started = 150
Jan 20 11:36:00 tox websentry-proxy-start[7184]: 2024/01/20 11:36:00 prop_0x0108 ("time") changed 11:35:43 => 11:35:59
Jan 20 11:36:00 tox websentry-proxy-start[7184]: 2024/01/20 11:36:00 prop_0x0600 ("humidity_percent") changed 55.2 => 54.9
Jan 20 11:36:00 tox websentry-proxy-start[7184]: 2024/01/20 11:36:00 prop_0x0602 ("supply_air_f") changed 76.2 => 77.2
Jan 20 11:36:00 tox websentry-proxy-start[7184]: 2024/01/20 11:36:00 prop_0x0603 ("outside_air_f") changed 64.4 => 64.5
Jan 20 11:36:00 tox websentry-proxy-start[7184]: 2024/01/20 11:36:00 prop_0x0607 ("low_pressure_psi") changed 198 => 197.4

Jan 20 11:36:01 tox websentry-proxy-start[7184]: 2024/01/20 11:36:01 sessions_ended = 150
Jan 20 11:36:17 tox websentry-proxy-start[7184]: 2024/01/20 11:36:17 sessions_started = 151
Jan 20 11:36:17 tox websentry-proxy-start[7184]: 2024/01/20 11:36:17 prop_0x1220 changed 0 => 100
Jan 20 11:36:17 tox websentry-proxy-start[7184]: 2024/01/20 11:36:17 prop_0x0108 ("time") changed 11:35:59 => 11:36:16
Jan 20 11:36:17 tox websentry-proxy-start[7184]: 2024/01/20 11:36:17 prop_0x0600 ("humidity_percent") changed 54.9 => 55.2
Jan 20 11:36:17 tox websentry-proxy-start[7184]: 2024/01/20 11:36:17 prop_0x0602 ("supply_air_f") changed 77.2 => 77.1
Jan 20 11:36:17 tox websentry-proxy-start[7184]: 2024/01/20 11:36:17 prop_0x0603 ("outside_air_f") changed 64.5 => 64.6
Jan 20 11:36:17 tox websentry-proxy-start[7184]: 2024/01/20 11:36:17 prop_0x0606 ("high_pressure_psi") changed 192.3 => 191.6
Jan 20 11:36:17 tox websentry-proxy-start[7184]: 2024/01/20 11:36:17 prop_0x0607 ("low_pressure_psi") changed 197.4 => 197.2
Jan 20 11:36:17 tox websentry-proxy-start[7184]: 2024/01/20 11:36:17 prop_0x0609 ("suction_temp_f") changed 85 => 85.2
Jan 20 11:36:17 tox websentry-proxy-start[7184]: 2024/01/20 11:36:17 prop_0x0610 ("discharge_temp_f") changed 76.9 => 77
Jan 20 11:36:17 tox websentry-proxy-start[7184]: 2024/01/20 11:36:17 prop_0x091e changed true(et=1) => false(et=1)
Jan 20 11:36:18 tox websentry-proxy-start[7184]: 2024/01/20 11:36:18 sessions_ended = 151

Jan 20 11:36:33 tox websentry-proxy-start[7184]: 2024/01/20 11:36:33 sessions_started = 152
Jan 20 11:36:33 tox websentry-proxy-start[7184]: 2024/01/20 11:36:33 prop_0x0108 ("time") changed 11:36:16 => 11:36:32
Jan 20 11:36:33 tox websentry-proxy-start[7184]: 2024/01/20 11:36:33 prop_0x0601 ("room_temp_f") changed 69.7 => 69.6
Jan 20 11:36:33 tox websentry-proxy-start[7184]: 2024/01/20 11:36:33 prop_0x0602 ("supply_air_f") changed 77.1 => 76.9
Jan 20 11:36:33 tox websentry-proxy-start[7184]: 2024/01/20 11:36:33 prop_0x0606 ("high_pressure_psi") changed 191.6 => 191.8
Jan 20 11:36:33 tox websentry-proxy-start[7184]: 2024/01/20 11:36:33 prop_0x0607 ("low_pressure_psi") changed 197.2 => 196.6
Jan 20 11:36:33 tox websentry-proxy-start[7184]: 2024/01/20 11:36:33 prop_0x0608 ("evaporator_temp_f") changed 64.6 => 64.5
Jan 20 11:36:33 tox websentry-proxy-start[7184]: 2024/01/20 11:36:33 prop_0x0609 ("suction_temp_f") changed 85.2 => 85.4
Jan 20 11:36:34 tox websentry-proxy-start[7184]: 2024/01/20 11:36:34 prop_0x0e02 changed 0 => 1
Jan 20 11:36:34 tox websentry-proxy-start[7184]: 2024/01/20 11:36:34 prop_0x100f changed 1 => 3
Jan 20 11:36:34 tox websentry-proxy-start[7184]: 2024/01/20 11:36:34 prop_0x120e ("blower_state") changed 0 => 2
Jan 20 11:36:34 tox websentry-proxy-start[7184]: 2024/01/20 11:36:34 prop_0x1227 changed 0 => 2
Jan 20 11:36:34 tox websentry-proxy-start[7184]: 2024/01/20 11:36:34 prop_0x1336 changed 0 => 2
Jan 20 11:36:34 tox websentry-proxy-start[7184]: 2024/01/20 11:36:34 prop_0x1612 changed 5 => 0
Jan 20 11:36:34 tox websentry-proxy-start[7184]: 2024/01/20 11:36:34 prop_0x190a changed 0 => 1
Jan 20 11:36:34 tox websentry-proxy-start[7184]: 2024/01/20 11:36:34 prop_0x1a04 changed 0 => 1
Jan 20 11:36:35 tox websentry-proxy-start[7184]: 2024/01/20 11:36:35 sessions_ended = 152

### Changing humidity from 54 to 50

Jan 20 20:58:38 tox websentry-proxy-start[7764]: 2024/01/20 20:58:38 sessions_started = 84
Jan 20 20:58:38 tox websentry-proxy-start[7764]: 2024/01/20 20:58:38 prop_0x0108 ("time") changed 20:58:21 => 20:58:37
Jan 20 20:58:38 tox websentry-proxy-start[7764]: 2024/01/20 20:58:38 [ 4]: S: 03 25 01 03 00 32
Jan 20 20:58:38 tox websentry-proxy-start[7764]: 2024/01/20 20:58:38 prop_0x0108 ("time") changed 20:58:37 => 20:58:38
Jan 20 20:58:39 tox websentry-proxy-start[7764]: 2024/01/20 20:58:39 prop_0x2501 ("set_humidity_percent") changed 54 (35-85 by 1) => 50 (35-85 by 1)
Jan 20 20:58:39 tox websentry-proxy-start[7764]: 2024/01/20 20:58:39 prop_0x250d changed 54 (35-85 by 1) => 50 (35-85 by 1)
Jan 20 20:58:40 tox websentry-proxy-start[7764]: 2024/01/20 20:58:40 prop_0x0603 ("outside_air_f") changed 64.5 => 64.6
Jan 20 20:58:40 tox websentry-proxy-start[7764]: 2024/01/20 20:58:40 prop_0x0606 ("high_pressure_psi") changed 189.7 => 190.6
Jan 20 20:58:40 tox websentry-proxy-start[7764]: 2024/01/20 20:58:40 prop_0x0607 ("low_pressure_psi") changed 195.6 => 195.1
Jan 20 20:58:41 tox websentry-proxy-start[7764]: 2024/01/20 20:58:41 prop_0x0e0c ("adv_control_status_internal_heat_on") changed 0 => 4
Jan 20 20:58:41 tox websentry-proxy-start[7764]: 2024/01/20 20:58:41 prop_0x1a18 ("adv_control_status_internal_room_heat") changed 20 => 3
Jan 20 20:58:42 tox websentry-proxy-start[7764]: 2024/01/20 20:58:42 prop_0x0108 ("time") changed 20:58:38 => 20:58:41
Jan 20 20:58:43 tox websentry-proxy-start[7764]: 2024/01/20 20:58:43 sessions_ended = 84
Jan 20 20:58:58 tox websentry-proxy-start[7764]: 2024/01/20 20:58:58 sessions_started = 85
Jan 20 20:58:58 tox websentry-proxy-start[7764]: 2024/01/20 20:58:58 prop_0x0108 ("time") changed 20:58:41 => 20:58:58
Jan 20 20:58:59 tox websentry-proxy-start[7764]: 2024/01/20 20:58:59 prop_0x0606 ("high_pressure_psi") changed 190.6 => 190.2
Jan 20 20:58:59 tox websentry-proxy-start[7764]: 2024/01/20 20:58:59 prop_0x0607 ("low_pressure_psi") changed 195.1 => 195.7
Jan 20 20:58:59 tox websentry-proxy-start[7764]: 2024/01/20 20:58:59 prop_0x0609 ("suction_temp_f") changed 85.5 => 85.6
Jan 20 20:58:59 tox websentry-proxy-start[7764]: 2024/01/20 20:58:59 prop_0x0e0c ("adv_control_status_internal_heat_on") changed 4 => 6
Jan 20 20:58:59 tox websentry-proxy-start[7764]: 2024/01/20 20:58:59 prop_0x190f changed 0 => 1
Jan 20 20:58:59 tox websentry-proxy-start[7764]: 2024/01/20 20:58:59 prop_0x1a18 ("adv_control_status_internal_room_heat") changed 3 => 6
Jan 20 20:59:00 tox websentry-proxy-start[7764]: 2024/01/20 20:59:00 sessions_ended = 85

Jan 20 20:59:31 tox websentry-proxy-start[7764]: 2024/01/20 20:59:31 sessions_started = 87
Jan 20 20:59:32 tox websentry-proxy-start[7764]: 2024/01/20 20:59:32 prop_0x0108 ("time") changed 20:59:14 => 20:59:31
Jan 20 20:59:32 tox websentry-proxy-start[7764]: 2024/01/20 20:59:32 prop_0x0600 ("humidity_percent") changed 55.4 => 55.3
Jan 20 20:59:32 tox websentry-proxy-start[7764]: 2024/01/20 20:59:32 prop_0x0601 ("room_temp_f") changed 69.4 => 69.3
Jan 20 20:59:32 tox websentry-proxy-start[7764]: 2024/01/20 20:59:32 prop_0x0607 ("low_pressure_psi") changed 195.1 => 195.5
Jan 20 20:59:32 tox websentry-proxy-start[7764]: 2024/01/20 20:59:32 prop_0x0e0c ("adv_control_status_internal_heat_on") changed 0 => 2
Jan 20 20:59:32 tox websentry-proxy-start[7764]: 2024/01/20 20:59:32 prop_0x190f changed 2 => 3
Jan 20 20:59:32 tox websentry-proxy-start[7764]: 2024/01/20 20:59:32 prop_0x1a18 ("adv_control_status_internal_room_heat") changed 10 => 13
Jan 20 20:59:33 tox websentry-proxy-start[7764]: 2024/01/20 20:59:33 sessions_ended = 87


*/

var crc16Tab = crc16.MakeTable(crc16.CRC16_MODBUS)

func checksum(b []byte) uint16 {
	return crc16.Checksum(b, crc16Tab)
}

func putChecksum(dst, pay []byte) {
	binary.BigEndian.PutUint16(dst, checksum(pay))
}
