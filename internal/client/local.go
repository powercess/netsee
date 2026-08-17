package client

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strings"
)

// InterfaceInfo is a local network interface as seen by the client.
type InterfaceInfo struct {
	Name     string   `json:"name"`
	MTU      int      `json:"mtu"`
	Up       bool     `json:"up"`
	Loopback bool     `json:"loopback"`
	Addrs    []string `json:"addrs"`
}

// ResolvConf is the parsed system resolver configuration.
type ResolvConf struct {
	Nameservers []string `json:"nameservers"`
	Search      []string `json:"search"`
}

// LocalInfo is the client's view of its own network environment.
type LocalInfo struct {
	Hostname       string          `json:"hostname"`
	Interfaces     []InterfaceInfo `json:"interfaces"`
	DefaultRouteV4 string          `json:"default_route_v4,omitempty"` // interface name
	DefaultGWV4    string          `json:"default_gw_v4,omitempty"`
	DefaultRouteV6 string          `json:"default_route_v6,omitempty"`
	DefaultMTU     int             `json:"default_mtu"`
	ResolvConf     *ResolvConf     `json:"resolv_conf,omitempty"`
	RouteSource    string          `json:"route_source"` // "proc" | "unsupported"
}

// collectInterfaces gathers interfaces via the net package (cross-platform).
func collectInterfaces() []InterfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]InterfaceInfo, 0, len(ifaces))
	for _, f := range ifaces {
		ii := InterfaceInfo{
			Name:     f.Name,
			MTU:      f.MTU,
			Up:       f.Flags&net.FlagUp != 0,
			Loopback: f.Flags&net.FlagLoopback != 0,
		}
		if addrs, err := f.Addrs(); err == nil {
			for _, a := range addrs {
				ii.Addrs = append(ii.Addrs, a.String())
			}
		}
		out = append(out, ii)
	}
	return out
}

// parseResolvConf parses /etc/resolv.conf style content (nameserver,
// search, domain lines). Unknown/unsupported directives are ignored.
func parseResolvConf(data []byte) *ResolvConf {
	rc := &ResolvConf{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "nameserver":
			if len(fields) >= 2 {
				rc.Nameservers = append(rc.Nameservers, fields[1])
			}
		case "search":
			rc.Search = append(rc.Search, fields[1:]...)
		case "domain":
			if len(fields) >= 2 {
				rc.Search = []string{fields[1]}
			}
		}
	}
	return rc
}

func readResolvConf() *ResolvConf {
	if runtime.GOOS == "windows" {
		return nil
	}
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return parseResolvConf(data)
}
