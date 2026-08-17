//go:build !linux

package probe

import "net"

// udpReader reads datagrams without TTL capture (IP_RECVTTL is
// Linux-specific).
type udpReader struct {
	conn *net.UDPConn
}

func newUDPReader(conn *net.UDPConn) *udpReader { return &udpReader{conn: conn} }

func (r *udpReader) read(buf []byte) (n int, src *net.UDPAddr, ttl int, err error) {
	n, src, err = r.conn.ReadFromUDP(buf)
	return n, src, 0, err
}
