package client

import (
	"net/netip"
	"strings"
)

// fakeIPRange is the range used by TUN proxies in fake-ip mode.
var fakeIPRange = netip.MustParsePrefix("198.18.0.0/15")

// Attribution is the TUN/fake-ip/proxy path-attribution layer. It must
// prevent reporting a proxy exit as the local environment (the doc's
// correctness requirement).
type Attribution struct {
	TUN          bool        `json:"tun"`
	TUNInterface string      `json:"tun_interface,omitempty"`
	FakeIP       bool        `json:"fake_ip"`
	FakeIPNote   string      `json:"fake_ip_note,omitempty"`
	ProxyStack   *ProxyStack `json:"proxy_stack,omitempty"`
	UDP          string      `json:"udp"` // "tun-blocked" | "unknown"
	Note         string      `json:"note,omitempty"`
}

// ProxyStack is a heuristic match of the probe-observed stack against
// known proxy implementations. Matches are LOW confidence and short-lived
// (fingerprints rotate with software updates); unknown stacks are not
// named (honest per the baseline).
type ProxyStack struct {
	Name       string `json:"name"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence"`
}

// isTUNInterface reports whether the interface name indicates a TUN/WG
// virtual device.
func isTUNInterface(name string) bool {
	for _, p := range []string{"tun", "utun", "wg", "tun0"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// detectTUN derives TUN state from the local environment.
func detectTUN(local *LocalInfo) (bool, string) {
	for _, name := range []string{local.DefaultRouteV4, local.DefaultRouteV6} {
		if name != "" && isTUNInterface(name) {
			return true, name
		}
	}
	return false, ""
}

// isFakeIP reports whether the address is inside the fake-ip range.
func isFakeIP(addr string) bool {
	ap, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return fakeIPRange.Contains(ap)
}

// detectFakeIPResolvers reports whether any system resolver sits inside
// the fake-ip range (a strong TUN-proxy signal).
func detectFakeIPResolvers(rc *ResolvConf) bool {
	if rc == nil {
		return false
	}
	for _, ns := range rc.Nameservers {
		if isFakeIP(ns) {
			return true
		}
	}
	return false
}

// detectFakeIPAnswer reports whether any DNS answer lies in the fake-ip
// range.
func detectFakeIPAnswer(answers []string) bool {
	for _, a := range answers {
		if isFakeIP(a) {
			return true
		}
	}
	return false
}

// GoStackJA3Hashes are measured JA3 hashes of Go's crypto/tls ClientHello.
// Go 1.26.6 measured 2026-08-17 on amd64. Fingerprints rotate with
// software updates (短保质期), so matches are low-confidence and the
// table is expected to drift.
var goStackJA3Hashes = []string{
	"9b7dcdf3f997f1fb7b4409c94cb7ef36", // Go 1.26.6 crypto/tls, default config
}

// inferProxyStack matches probe-observed fingerprints against known
// proxy stacks. Returns nil when nothing matches (the exit is then only
// labeled "proxy exit", never named).
func inferProxyStack(observations []Observation) *ProxyStack {
	for _, obs := range observations {
		if obs.JA3 == "" {
			continue
		}
		for _, h := range goStackJA3Hashes {
			if obs.JA3 == h {
				return &ProxyStack{
					Name:       "Go 运行时栈（clash/sing-box 类代理）",
					Confidence: "低（指纹随版本变化，保质期短）",
					Evidence:   "JA3 哈希匹配 Go crypto/tls 实测值（Go 1.26.6）",
				}
			}
		}
	}
	return nil
}
