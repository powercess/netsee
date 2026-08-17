//go:build !linux

package client

import (
	"errors"
	"os"
)

// CollectLocal gathers the local network environment. Default-route
// parsing relies on /proc and is Linux-only; other platforms report
// interfaces and (on Unix) resolv.conf.
func CollectLocal() (*LocalInfo, error) {
	info := &LocalInfo{RouteSource: "unsupported"}
	info.Hostname, _ = os.Hostname()
	info.Interfaces = collectInterfaces()
	info.ResolvConf = readResolvConf()
	return info, nil
}

// PhysicalDefaultV4 is Linux-only.
func PhysicalDefaultV4() (string, string, error) {
	return "", "", errors.New("物理默认路由解析仅在 Linux 支持")
}
