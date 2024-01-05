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

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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

type proxy struct {
	mu sync.Mutex
}

func (p *proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

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
}

type proxySession struct {
	p    *proxy
	c    *net.TCPConn // incoming (from unit)
	outc *net.TCPConn

	mu     sync.Mutex
	pktNum int
}

func (s *proxySession) run() {
	errc := make(chan error, 2)
	go func() {
		errc <- s.copy("C", s.c, s.outc)
	}()
	go func() {
		errc <- s.copy("S", s.outc, s.c)
	}()
	if err := <-errc; err != nil {
		log.Printf("proxy session error: %v", err)
	}
	if err := <-errc; err != nil {
		log.Printf("proxy session error: %v", err)
	}
}

func (s *proxySession) nextPktNum() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pktNum++
	return s.pktNum
}

func (s *proxySession) copy(srcName string, src, dst *net.TCPConn) error {
	buf := make([]byte, 4<<10)
	defer dst.CloseWrite()
	for {
		_, err := io.ReadFull(src, buf[:pktHeaderLen])
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("%v: header read error: %v", srcName, err)
		}

		payLen := int(buf[5])<<8 | int(buf[6])
		if payLen > len(buf)-pktHeaderLen {
			return fmt.Errorf("%v: payload too big: %d", srcName, payLen)
		}
		_, err = io.ReadFull(src, buf[pktHeaderLen:][:payLen])
		if err != nil {
			return fmt.Errorf("%v: payload read error: %v", srcName, err)
		}
		totalLen := pktHeaderLen + payLen
		_, err = dst.Write(buf[:totalLen])
		if err != nil {
			return fmt.Errorf("%s: write to peer error: %v", srcName, err)
		}
		pktNum := s.nextPktNum()
		log.Printf("[%2d]: %s: % 02x", pktNum, srcName, buf[pktHeaderLen:totalLen])
	}
}
