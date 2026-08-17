package probe

import (
	"net"
	"strings"
	"time"

	"netsee/internal/proto"
)

// handleTLSConn sniffs the ClientHello of one accepted TLS connection.
// The probe never completes the handshake and never writes any payload:
// it reads until the ClientHello is parsed (or the deadline/cap is hit),
// records the observation, and closes. No certificate is needed because
// no handshake is performed (see docs/protocol/probe.md).
func (s *Server) handleTLSConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))

	parser := &helloParser{}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			ch, complete, perr := parser.Feed(buf[:n])
			if complete {
				if perr == nil {
					s.recordTLS(conn, ch)
				}
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// recordTLS stores the observed ClientHello fingerprint under the session
// carried in the SNI prefix "<session>.n".
func (s *Server) recordTLS(conn net.Conn, ch *clientHello) {
	session := ""
	if i := strings.IndexByte(ch.sni, '.'); i > 0 && proto.ValidSessionID(ch.sni[:i]) {
		session = ch.sni[:i]
	}
	obs := &proto.Obs{
		ID:      proto.NewID(),
		Kind:    proto.ObsTLS,
		Session: session,
		DstPort: s.info().TLSPort,
		Time:    time.Now(),
		TLS: &proto.TLSFingerprint{
			JA3: ch.JA3(),
			JA4: ch.JA4(),
			SNI: ch.sni,
		},
	}
	if host, port, err := splitHostPort(conn.RemoteAddr().String()); err == nil {
		obs.SrcIP, obs.SrcPort = host, port
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		if ti, err := tcpInfoFromConn(tc); err == nil {
			obs.TCPInfo = ti
		}
	}
	if session != "" {
		s.store.Append(session, obs)
	}
}
