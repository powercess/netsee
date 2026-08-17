package client

import (
	"testing"
)

const routeFixture = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
tun0	00000000	0101010A	0003	0	0	0	00000000	0	0	0
eth0	00000000	FEFEFEA9	0003	0	0	100	00000000	1500	0	0
eth0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`

// gateway FEFEFEA9 little-endian = 169.254.254.254; 0101010A = 10.1.1.1.

func TestParseRouteV4(t *testing.T) {
	iface, gw, err := parseRouteV4([]byte(routeFixture))
	if err != nil {
		t.Fatalf("parseRouteV4: %v", err)
	}
	// tun0 has metric 0 and would win, but parseRouteV4 must return the
	// lowest metric overall: tun0 (0) beats eth0 (100).
	if iface != "tun0" || gw != "10.1.1.1" {
		t.Errorf("default = %s via %s, want tun0 via 10.1.1.1", iface, gw)
	}
}

func TestParsePhysicalV4(t *testing.T) {
	iface, gw, err := parsePhysicalV4([]byte(routeFixture))
	if err != nil {
		t.Fatalf("parsePhysicalV4: %v", err)
	}
	// tun0 must be skipped: physical default is eth0 via 169.254.254.254.
	if iface != "eth0" || gw != "169.254.254.254" {
		t.Errorf("physical default = %s via %s, want eth0 via 169.254.254.254", iface, gw)
	}
}

const v6RouteFixture = `00000000000000000000000000000000 00 00000000000000000000000000000000 00 0000000000000000 00000000 00000000 00000001 00000000 wg0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 0000000000000000 00000000 00000000 00000001 00000000 eth0
`

func TestParseRouteV6(t *testing.T) {
	iface, err := parseRouteV6([]byte(v6RouteFixture))
	if err != nil {
		t.Fatalf("parseRouteV6: %v", err)
	}
	if iface != "wg0" {
		t.Errorf("v6 default = %s, want wg0", iface)
	}
}

func TestParseResolvConf(t *testing.T) {
	rc := parseResolvConf([]byte(`
# comment
nameserver 198.18.0.1
nameserver 8.8.8.8
search corp.example example.com
`))
	if len(rc.Nameservers) != 2 || rc.Nameservers[0] != "198.18.0.1" || rc.Nameservers[1] != "8.8.8.8" {
		t.Errorf("nameservers = %v", rc.Nameservers)
	}
	if len(rc.Search) != 2 || rc.Search[0] != "corp.example" {
		t.Errorf("search = %v", rc.Search)
	}
}

func TestParseResolvDomainOverrides(t *testing.T) {
	// "domain" and "search" are mutually exclusive; the later directive
	// wins per resolv.conf semantics.
	rc := parseResolvConf([]byte("search a.example b.example\ndomain c.example\n"))
	if len(rc.Search) != 1 || rc.Search[0] != "c.example" {
		t.Errorf("search = %v, want [c.example]", rc.Search)
	}
}

func TestHexLEToIPv4(t *testing.T) {
	cases := map[string]string{
		"FEFEFEA9": "169.254.254.254",
		"0101010A": "10.1.1.1",
		"7F000001": "1.0.0.127",
		"00000000": "0.0.0.0",
		"zz":       "",
	}
	for in, want := range cases {
		if got := hexLEToIPv4(in); got != want {
			t.Errorf("hexLEToIPv4(%q) = %q, want %q", in, got, want)
		}
	}
}
