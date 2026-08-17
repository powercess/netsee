//go:build linux

package probe

import (
	"net"

	"golang.org/x/sys/unix"

	"netsee/internal/proto"
)

// tcpi option bits from linux/include/uapi/linux/tcp.h (x/sys does not
// export them).
const (
	tcpiOptTimestamps = 1 << 0
	tcpiOptSACK       = 1 << 1
	tcpiOptWScale     = 1 << 2
	tcpiOptECN        = 1 << 3
)

// tcpInfoFromConn reads the kernel TCP_INFO for an accepted TCP
// connection: the peer fingerprint (MSS, negotiated options, smoothed
// RTT) as seen by the probe.
func tcpInfoFromConn(conn *net.TCPConn) (*proto.TCPInfo, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var info *unix.TCPInfo
	var serr error
	if err := raw.Control(func(fd uintptr) {
		info, serr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, serr
	}
	return &proto.TCPInfo{
		MSS:    info.Snd_mss,
		WScale: info.Options&tcpiOptWScale != 0,
		SACK:   info.Options&tcpiOptSACK != 0,
		TS:     info.Options&tcpiOptTimestamps != 0,
		ECN:    info.Options&tcpiOptECN != 0,
		RTTUs:  info.Rtt,
	}, nil
}
