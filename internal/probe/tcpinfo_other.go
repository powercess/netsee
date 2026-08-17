//go:build !linux

package probe

import (
	"errors"
	"net"

	"netsee/internal/proto"
)

// tcpInfoFromConn is unavailable on non-Linux platforms: TCP_INFO is a
// Linux-specific socket option. The probe simply omits the fingerprint.
func tcpInfoFromConn(*net.TCPConn) (*proto.TCPInfo, error) {
	return nil, errors.New("TCP_INFO unsupported on this platform")
}
