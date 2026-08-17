//go:build !linux

package client

import (
	"errors"
	"net"
)

func setPMTUDiscDo(*net.UDPConn) error {
	return errors.New("IP_PMTUDISC unsupported on this platform")
}
