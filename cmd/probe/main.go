// Command netsee-probe is the remote observation point of NetSee.
// It records "what the network sees" about client connections and
// exposes them per session over HTTP.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"netsee/internal/probe"
)

func main() {
	cfg := probe.Config{}
	flag.StringVar(&cfg.Bind, "bind", "0.0.0.0", "bind address")
	flag.IntVar(&cfg.HTTPPort, "http-port", 8080, "HTTP echo + control API port")
	flag.IntVar(&cfg.TLSPort, "tls-port", 8443, "TLS ClientHello sniff port (sniff-only, no handshake)")
	flag.IntVar(&cfg.UDPPort, "udp-port", 8444, "UDP echo port")
	flag.IntVar(&cfg.NATPort, "nat-port", 8445, "UDP NAT reply port")
	extra := flag.String("extra-ports", "", "comma-separated extra TCP ports (port-block testing)")
	flag.StringVar(&cfg.SecondIP, "second-ip", "", "second IP for NAT replies (full RFC 5780 classification)")
	flag.DurationVar(&cfg.TTL, "ttl", 5*time.Minute, "session registry TTL")
	flag.IntVar(&cfg.MaxSessions, "max-sessions", 10000, "max concurrent sessions")
	flag.IntVar(&cfg.MaxUDP, "max-udp", 2048, "max UDP payload echoed (bytes)")
	flag.IntVar(&cfg.MaxUDPPMTU, "max-udp-pmtu", 9000, "max UDP payload echoed for pmtu kind (bytes)")
	flag.DurationVar(&cfg.ReadTimeout, "read-timeout", 10*time.Second, "per-connection read timeout")
	flag.Parse()

	if *extra != "" {
		for _, p := range strings.Split(*extra, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || n <= 0 || n > 65535 {
				log.Fatalf("invalid extra port %q", p)
			}
			cfg.ExtraPorts = append(cfg.ExtraPorts, n)
		}
	}

	srv := probe.New(cfg)
	if err := srv.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}
	info := srv.Ports()
	log.Printf("netsee-probe listening: http=%s:%d tls=%s:%d udp=%s:%d nat=%s:%d extra=%v second_ip=%v",
		cfg.Bind, info.HTTPPort, cfg.Bind, info.TLSPort, cfg.Bind, info.UDPPort, cfg.Bind, info.NATPort,
		info.ExtraPorts, cfg.SecondIP)
	if info.HTTPPort < 1024 || info.TLSPort < 1024 || info.UDPPort < 1024 || info.NATPort < 1024 {
		log.Printf("note: ports below 1024 require root or CAP_NET_BIND_SERVICE")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Printf("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}
