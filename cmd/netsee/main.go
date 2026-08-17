// Command netsee is the NetSee client: it measures the client's network
// exposure through a probe and produces a structured result (rendered by
// the report layer in P3).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netsee/internal/client"
	"netsee/internal/report"
	"netsee/internal/version"
)

func main() {
	var (
		probeURL    = flag.String("probe", "http://127.0.0.1:8080", "probe base URL")
		timeout     = flag.Duration("timeout", 15*time.Second, "per-measurement timeout")
		doh         = flag.String("doh", "https://dns.google/resolve", "DoH endpoint; empty disables the DNS comparison")
		dnsHost     = flag.String("dns-host", "example.com", "hostname used for the DNS hijack comparison")
		ipinfoToken = flag.String("ipinfo-token", "", "optional ipinfo.io access token")
		direct      = flag.Bool("direct", false, "also measure via a direct route bypassing TUN (needs root)")
		asJSON      = flag.Bool("json", false, "output the full structured result as JSON")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("netsee", version.Version)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := client.Config{
		ProbeURL:    *probeURL,
		Timeout:     *timeout,
		DoHURL:      *doh,
		DNSHost:     *dnsHost,
		IPInfoToken: *ipinfoToken,
		Direct:      *direct,
	}
	res, err := cfg.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netsee: %v\n", err)
		os.Exit(1)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report.Build(res)); err != nil {
			fmt.Fprintf(os.Stderr, "netsee: encode: %v\n", err)
			os.Exit(1)
		}
		return
	}
	report.Build(res).RenderText(os.Stdout)
}
