package client_test

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"netsee/internal/client"
	"netsee/internal/probe"
)

func startProbe(t *testing.T) *probe.Server {
	t.Helper()
	srv := probe.New(probe.Config{
		Bind:        "127.0.0.1",
		HTTPPort:    0,
		TLSPort:     0,
		UDPPort:     0,
		NATPort:     0,
		TTL:         time.Minute,
		MaxUDP:      2048,
		MaxUDPPMTU:  9000,
		ReadTimeout: 5 * time.Second,
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("probe start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return srv
}

func testConfig(url string) client.Config {
	return client.Config{
		ProbeURL:  url,
		Timeout:   3 * time.Second,
		DoHURL:    "", // keep the suite hermetic
		IPAPIBase: "http://127.0.0.1:1/json",
		DNSHost:   "example.com",
	}
}

func TestFullClientRunLoopback(t *testing.T) {
	srv := startProbe(t)
	info := srv.Ports()
	url := fmt.Sprintf("http://127.0.0.1:%d", info.HTTPPort)

	res, err := testConfig(url).Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Session == "" {
		t.Error("empty session")
	}
	if res.Duration <= 0 {
		t.Error("duration not set")
	}

	found := false
	for _, ip := range res.Probe.ExitIPs {
		if ip == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("exit IPs = %v, want 127.0.0.1", res.Probe.ExitIPs)
	}

	if res.NAT == nil {
		t.Fatal("NAT missing")
	}
	if res.NAT.Label != "直连（无 NAT 翻译）" {
		t.Errorf("NAT label = %q, want 直连", res.NAT.Label)
	}
	if len(res.NAT.Facts) < 4 {
		t.Errorf("NAT facts = %d, want >= 4 (raw facts before label)", len(res.NAT.Facts))
	}

	if res.Attribution.TUN {
		t.Error("TUN flagged on loopback")
	}
	if res.Attribution.FakeIP {
		t.Error("fake-ip flagged on loopback")
	}

	if runtime.GOOS == "linux" {
		if res.PMTU == nil {
			t.Fatal("PMTU missing on linux")
		}
		if res.PMTU.PathMTU == 0 {
			t.Errorf("PMTU = 0: %+v", res.PMTU)
		}
		if res.PMTU.Blackhole {
			t.Error("blackhole flagged on loopback")
		}
	}

	if res.DNS != nil && res.DNS.DoHStatus != "skipped" {
		t.Errorf("DoH status = %q, want skipped", res.DNS.DoHStatus)
	}

	if res.Reputation == nil || res.Reputation.Source != "unavailable" {
		t.Errorf("reputation = %+v, want unavailable", res.Reputation)
	}

	for _, pc := range res.Probe.Connectivity {
		if !pc.Connected {
			t.Errorf("port %d not connected on loopback", pc.Port)
		}
		if !pc.ProbeSaw {
			t.Errorf("port %d: probe did not observe", pc.Port)
		}
		if !pc.Consistent {
			t.Errorf("port %d inconsistent: connected=%v saw=%v", pc.Port, pc.Connected, pc.ProbeSaw)
		}
	}

	hasContext := false
	for _, n := range res.Notes {
		if n.Level == "info" {
			hasContext = true
		}
	}
	if !hasContext {
		t.Error("honest-context note missing")
	}
}

func TestDirectDegradesOnLoopback(t *testing.T) {
	srv := startProbe(t)
	info := srv.Ports()
	cfg := testConfig(fmt.Sprintf("http://127.0.0.1:%d", info.HTTPPort))
	cfg.Direct = true

	res, err := cfg.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Direct != nil {
		t.Error("direct should not be produced when the probe is on loopback")
	}
	hasNote := false
	for _, n := range res.Notes {
		if n.Level == "warn" && strings.Contains(n.Text, "直连对比不可用") {
			hasNote = true
		}
	}
	if !hasNote {
		t.Error("expected an explicit direct-unavailable warning note")
	}
}

// TestProbeUnreachableFailsFast verifies ACC-P4-003: an unreachable probe
// must fail clearly within 60s (port 1 is closed → connection refused).
func TestProbeUnreachableFailsFast(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	started := time.Now()
	_, err := cfg.Run(context.Background())
	if err == nil {
		t.Fatal("expected an error for an unreachable probe")
	}
	if d := time.Since(started); d > 60*time.Second {
		t.Errorf("unreachable probe took %v, want <= 60s", d)
	}
	if !strings.Contains(err.Error(), "probe /api/info") {
		t.Errorf("unexpected error: %v", err)
	}
}
