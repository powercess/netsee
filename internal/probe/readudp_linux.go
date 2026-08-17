//go:build linux

package probe

import (
	"net"

	"golang.org/x/sys/unix"
)

// udpReader wraps a UDP socket to also deliver the received TTL via the
// IP_RECVTTL ancillary message (no root required for UDP).
type udpReader struct {
	conn *net.UDPConn
	oob  []byte
}

func newUDPReader(conn *net.UDPConn) *udpReader {
	r := &udpReader{conn: conn, oob: make([]byte, 64)}
	if raw, err := conn.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTTL, 1)
		})
	}
	return r
}

func (r *udpReader) read(buf []byte) (n int, src *net.UDPAddr, ttl int, err error) {
	n, oobn, _, src, err := r.conn.ReadMsgUDP(buf, r.oob)
	if err != nil || oobn == 0 {
		return n, src, 0, err
	}
	cmsgs, perr := unix.ParseSocketControlMessage(r.oob[:oobn])
	if perr != nil {
		return n, src, 0, err
	}
	for _, cm := range cmsgs {
		if cm.Header.Level == unix.IPPROTO_IP && cm.Header.Type == unix.IP_TTL && len(cm.Data) > 0 {
			ttl = int(cm.Data[0])
		}
	}
	return n, src, ttl, err
}
