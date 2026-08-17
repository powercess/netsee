package client

import (
	"testing"
)

func TestIsTUNInterface(t *testing.T) {
	for _, name := range []string{"tun0", "utun3", "wg0", "tun"} {
		if !isTUNInterface(name) {
			t.Errorf("isTUNInterface(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"eth0", "enp3s0", "wlan0", "lo", "docker0"} {
		if isTUNInterface(name) {
			t.Errorf("isTUNInterface(%q) = true, want false", name)
		}
	}
}

func TestFakeIP(t *testing.T) {
	for _, ip := range []string{"198.18.0.1", "198.19.255.255", "198.18.5.5"} {
		if !isFakeIP(ip) {
			t.Errorf("isFakeIP(%q) = false, want true", ip)
		}
	}
	for _, ip := range []string{"198.17.255.255", "198.20.0.1", "8.8.8.8", "127.0.0.1"} {
		if isFakeIP(ip) {
			t.Errorf("isFakeIP(%q) = true, want false", ip)
		}
	}
}

func TestDetectFakeIPResolvers(t *testing.T) {
	if !detectFakeIPResolvers(&ResolvConf{Nameservers: []string{"198.18.0.1", "8.8.8.8"}}) {
		t.Error("fake-ip resolver not detected")
	}
	if detectFakeIPResolvers(&ResolvConf{Nameservers: []string{"8.8.8.8"}}) {
		t.Error("false positive for non-fake-ip resolver")
	}
	if detectFakeIPResolvers(nil) {
		t.Error("nil resolv.conf flagged")
	}
}

func TestDetectFakeIPAnswer(t *testing.T) {
	if !detectFakeIPAnswer([]string{"198.18.1.2"}) {
		t.Error("fake-ip answer not detected")
	}
	if detectFakeIPAnswer([]string{"93.184.216.34"}) {
		t.Error("false positive for normal answer")
	}
}

func TestInferProxyStack(t *testing.T) {
	// Go 1.26.6 measured JA3 hash must match.
	obs := []Observation{{Kind: "tls", JA3: "9b7dcdf3f997f1fb7b4409c94cb7ef36"}}
	if got := inferProxyStack(obs); got == nil {
		t.Fatal("Go stack hash not matched")
	} else if got.Name == "" {
		t.Error("empty stack name")
	}
	// Unknown stack must not be named.
	if got := inferProxyStack([]Observation{{Kind: "tls", JA3: "00000000000000000000000000000000"}}); got != nil {
		t.Errorf("unknown stack matched: %+v", got)
	}
	if got := inferProxyStack(nil); got != nil {
		t.Error("nil observations matched")
	}
}
