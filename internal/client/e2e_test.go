//go:build e2e

package client_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"netsee/internal/client"
	"netsee/internal/report"
)

// TestE2ERealNetwork runs the full client against a local probe using the
// REAL DoH endpoint and REAL ip-api (external network required; run with
// `go test -tags e2e ./internal/client/`). Hermetic defaults keep this
// out of the regular suite.
func TestE2ERealNetwork(t *testing.T) {
	srv := startProbe(t)
	info := srv.Ports()
	url := fmt.Sprintf("http://127.0.0.1:%d", info.HTTPPort)

	cfg := client.Config{
		ProbeURL:  url,
		Timeout:   10 * time.Second,
		DoHURL:    "https://dns.google/resolve",
		DNSHost:   "example.com",
		IPAPIBase: "http://ip-api.com/json",
	}

	started := time.Now()
	res, err := cfg.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if d := time.Since(started); d > 30*time.Second {
		t.Errorf("full run took %v, want <= 30s (NFR-PERF-001)", d)
	}

	// Real DoH comparison must complete.
	if res.DNS == nil || res.DNS.DoHStatus != "ok" {
		t.Fatalf("DNS DoH not ok: %+v", res.DNS)
	}
	// On a normal network, example.com must NOT be flagged as hijacked.
	if strings.Contains(res.DNS.Judgment, "疑似") && !res.DNS.FakeIPDetected {
		t.Errorf("false hijack on normal network: %+v", res.DNS)
	}
	// Reputation must not crash on a reserved IP (127.0.0.1 → ip-api fail).
	if res.Reputation == nil || res.Reputation.Source == "" {
		t.Errorf("reputation = %+v", res.Reputation)
	}

	// Report builds and renders with the real result.
	rep := report.Build(res)
	if rep.HonestContext == "" || rep.Overview.ExitCount == 0 {
		t.Errorf("report incomplete: %+v", rep.Overview)
	}
}
