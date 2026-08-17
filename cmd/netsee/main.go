// Command netsee is the NetSee client: it measures the client's network
// exposure through a probe and produces a structured result (rendered by
// the report layer in P3).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"netsee/internal/client"
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
	)
	flag.Parse()

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
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(os.Stderr, "netsee: encode: %v\n", err)
			os.Exit(1)
		}
		return
	}
	printSummary(os.Stdout, res)
}

// printSummary is the interim text output (P2). The full three-layer
// report rendering lands in P3 (internal/report).
func printSummary(w io.Writer, r *client.Result) {
	fmt.Fprintf(w, "netsee 会话 %s（%.1fs）\n", shortID(r.Session), r.Duration.Seconds())
	fmt.Fprintf(w, "本地: 默认路由 %s v4/%s v6, MTU %d, 接口 %d\n",
		orNA(r.Local.DefaultRouteV4), orNA(r.Local.DefaultRouteV6), r.Local.DefaultMTU, len(r.Local.Interfaces))
	if r.Attribution.TUN {
		fmt.Fprintf(w, "归因: [TUN %s 接管] 探针观测为代理出口\n", r.Attribution.TUNInterface)
		if r.Attribution.ProxyStack != nil {
			fmt.Fprintf(w, "  代理栈: %s（%s）\n", r.Attribution.ProxyStack.Name, r.Attribution.ProxyStack.Confidence)
		}
	} else {
		fmt.Fprintf(w, "归因: 无 TUN 接管\n")
	}
	if r.Attribution.FakeIP {
		fmt.Fprintf(w, "  fake-ip: 命中（%s）\n", r.Attribution.FakeIPNote)
	}
	fmt.Fprintf(w, "公网出口: %v\n", orNA(r.Probe.ExitIPs))
	if r.NAT != nil {
		fmt.Fprintf(w, "NAT: %s\n", r.NAT.Label)
	}
	if r.PMTU != nil {
		extra := ""
		if r.PMTU.Blackhole {
			extra = " [疑似 PMTU 黑洞]"
		}
		fmt.Fprintf(w, "PMTU: %d%s\n", r.PMTU.PathMTU, extra)
	}
	if r.DNS != nil {
		fmt.Fprintf(w, "DNS(%s): %s（系统 %d 条 / DoH %d 条）\n", r.DNS.Host, r.DNS.Judgment, len(r.DNS.SystemAnswers), len(r.DNS.DoHAnswers))
	}
	if r.Reputation != nil {
		where := fmt.Sprintf("%s %s %s %s", r.Reputation.Country, r.Reputation.Region, r.Reputation.City, r.Reputation.ISP)
		fmt.Fprintf(w, "信誉(%s): %s [%s]\n", r.Reputation.IP, strings.TrimSpace(where), r.Reputation.Source)
	}
	if r.Direct != nil {
		fmt.Fprintf(w, "直连对比: 出口 %v, NAT %s\n", r.Direct.Probe.ExitIPs, natLabel(r.Direct))
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "[%s] %s\n", n.Level, n.Text)
	}
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func orNA[T any](v T) any {
	switch x := any(v).(type) {
	case string:
		if x == "" {
			return "n/a"
		}
	case []string:
		if len(x) == 0 {
			return "n/a"
		}
	}
	return v
}

func natLabel(r *client.Result) string {
	if r.NAT == nil {
		return "n/a"
	}
	return r.NAT.Label
}
