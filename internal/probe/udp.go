package probe

import (
	"encoding/json"
	"net"
	"time"

	"netsee/internal/proto"
)

// serveUDP handles UDP echo/NAT/reach/pmtu datagrams. Echo-family kinds
// reply from the same socket; NAT replies from the NAT socket (different
// port, and different IP when -second-ip is set). TTL is captured on
// Linux via IP_RECVTTL (readudp_linux.go), elsewhere omitted.
func (s *Server) serveUDP() {
	defer s.wg.Done()
	r := newUDPReader(s.udpLn)
	buf := make([]byte, 65535)
	for {
		n, src, ttl, err := r.read(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			continue
		}
		if n == 0 || n > s.cfg.MaxUDP {
			continue // oversized: drop silently (THR-PROBE-001)
		}
		s.handleUDP(buf[:n], src, ttl)
	}
}

func (s *Server) handleUDP(payload []byte, src *net.UDPAddr, ttl int) {
	var m struct {
		Session string `json:"session"`
		Kind    string `json:"kind"`
	}
	if err := json.Unmarshal(payload, &m); err != nil || !proto.ValidSessionID(m.Session) {
		return
	}
	switch proto.UDPKind(m.Kind) {
	case proto.UDPEcho, proto.UDPReach, proto.UDPPMTU:
		s.recordUDP(m.Session, src, ttl, m.Kind, "same", len(payload))
		_, _ = s.udpLn.WriteToUDP(payload, src)
	case proto.UDPNat:
		from := "other-port"
		if s.cfg.SecondIP != "" {
			from = "other-ip"
		}
		s.recordUDP(m.Session, src, ttl, m.Kind, from, len(payload))
		_, _ = s.natLn.WriteToUDP(payload, src)
	}
}

func (s *Server) recordUDP(session string, src *net.UDPAddr, ttl int, kind, replyFrom string, payloadLen int) {
	obs := &proto.Obs{
		ID:      proto.NewID(),
		Kind:    proto.ObsUDP,
		Session: session,
		SrcIP:   src.IP.String(),
		SrcPort: src.Port,
		DstPort: s.info().UDPPort,
		TTL:     ttl,
		Time:    time.Now(),
		UDP: &proto.UDPObs{
			Kind:       kind,
			ReplyFrom:  replyFrom,
			PayloadLen: payloadLen,
		},
	}
	s.store.Append(session, obs)
}
