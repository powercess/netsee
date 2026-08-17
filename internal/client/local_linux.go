//go:build linux

package client

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
)

// CollectLocal gathers the local network environment. On Linux the
// default routes are parsed from /proc (no root required).
func CollectLocal() (*LocalInfo, error) {
	info := &LocalInfo{RouteSource: "proc"}
	info.Hostname, _ = os.Hostname()
	info.Interfaces = collectInterfaces()

	if iface, gw, err := defaultRouteV4(); err == nil {
		info.DefaultRouteV4, info.DefaultGWV4 = iface, gw
	}
	if iface, err := defaultRouteV6(); err == nil {
		info.DefaultRouteV6 = iface
	}
	if info.DefaultRouteV4 != "" {
		if f, err := net.InterfaceByName(info.DefaultRouteV4); err == nil {
			info.DefaultMTU = f.MTU
		}
	} else if info.DefaultRouteV6 != "" {
		if f, err := net.InterfaceByName(info.DefaultRouteV6); err == nil {
			info.DefaultMTU = f.MTU
		}
	}
	info.ResolvConf = readResolvConf()
	return info, nil
}

// defaultRouteV4 returns the interface and gateway of the default IPv4
// route (lowest metric) from /proc/net/route.
func defaultRouteV4() (iface, gw string, err error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", "", err
	}
	return parseRouteV4(data)
}

// parseRouteV4 parses /proc/net/route content (testable with fixtures).
func parseRouteV4(data []byte) (iface, gw string, err error) {
	bestMetric := -1
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		if fields[1] != "00000000" {
			continue
		}
		flags, ferr := strconv.ParseUint(fields[3], 16, 32)
		if ferr != nil || flags&0x1 == 0 {
			continue
		}
		metric, _ := strconv.Atoi(fields[6])
		if bestMetric < 0 || metric < bestMetric {
			bestMetric = metric
			iface = fields[0]
			gw = hexLEToIPv4(fields[2])
		}
	}
	if iface == "" {
		return "", "", errors.New("no default IPv4 route")
	}
	return iface, gw, nil
}

// defaultRouteV6 returns the interface of the default IPv6 route (lowest
// metric) from /proc/net/ipv6_route. The gateway is not present in this
// file, so only the interface is reported.
func defaultRouteV6() (string, error) {
	data, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return "", err
	}
	return parseRouteV6(data)
}

// parseRouteV6 parses /proc/net/ipv6_route content (testable).
func parseRouteV6(data []byte) (string, error) {
	bestMetric := -1
	iface := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[0] != "00000000000000000000000000000000" || fields[1] != "00" {
			continue
		}
		metric, merr := strconv.ParseUint(fields[4], 16, 32)
		if merr != nil {
			continue
		}
		if bestMetric < 0 || int(metric) < bestMetric {
			bestMetric = int(metric)
			iface = fields[9]
		}
	}
	if iface == "" {
		return "", errors.New("no default IPv6 route")
	}
	return iface, nil
}

// hexLEToIPv4 converts a little-endian hex IP (as stored in
// /proc/net/route) to dotted notation.
func hexLEToIPv4(h string) string {
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return ""
	}
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String()
}

// PhysicalDefaultV4 returns the lowest-metric default IPv4 route on a
// non-TUN interface: the underlying physical path, used by --direct to
// bypass the TUN proxy.
func PhysicalDefaultV4() (iface, gw string, err error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", "", err
	}
	return parsePhysicalV4(data)
}

// parsePhysicalV4 parses /proc/net/route content, skipping TUN routes.
func parsePhysicalV4(data []byte) (iface, gw string, err error) {
	bestMetric := -1
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 11 || fields[1] != "00000000" {
			continue
		}
		if isTUNInterface(fields[0]) {
			continue
		}
		flags, ferr := strconv.ParseUint(fields[3], 16, 32)
		if ferr != nil || flags&0x1 == 0 {
			continue
		}
		metric, _ := strconv.Atoi(fields[6])
		if bestMetric < 0 || metric < bestMetric {
			bestMetric = metric
			iface = fields[0]
			gw = hexLEToIPv4(fields[2])
		}
	}
	if iface == "" {
		return "", "", errors.New("no physical default IPv4 route")
	}
	return iface, gw, nil
}
