//go:build linux

package client

import (
	"net"

	"golang.org/x/sys/unix"
)

// setPMTUDiscDo enables IP_PMTUDISC_DO (DF bit) on a UDP socket: sendto
// of an oversized datagram then returns EMSGSIZE, which is how we bound
// the path MTU without root.
func setPMTUDiscDo(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
	}); err != nil {
		return err
	}
	return serr
}
