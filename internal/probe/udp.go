package probe

import (
	"encoding/json"
	"net"
	"time"

	"netsee/internal/proto"
)

// serveUDP handles datagrams arriving at the UDP echo port.
func (s *Server) serveUDP() {
	defer s.wg.Done()
	s.serveUDPLoop(s.udpLn, newUDPReader(s.udpLn))
}

// serveUDPNat handles datagrams arriving at the NAT reply port. Reading
// arrivals here lets the client compare the probe-observed source port
// for two different destinations (symmetric-mapping detection).
func (s *Server) serveUDPNat() {
	defer s.wg.Done()
	s.serveUDPLoop(s.natLn, newUDPReader(s.natLn))
}

func (s *Server) serveUDPLoop(ln *net.UDPConn, r *udpReader) {
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
		if n == 0 {
			continue
		}
		s.handleUDPArrival(ln, buf[:n], src, ttl)
	}
}

// handleUDPArrival processes one datagram. The reply source depends on
// kind: echo/reach/pmtu reply from the arrival socket (same port), nat
// replies from the NAT socket (different port, or different IP when
// -second-ip is set). reply_from is relative to the arrival port.
func (s *Server) handleUDPArrival(ln *net.UDPConn, payload []byte, src *net.UDPAddr, ttl int) {
	var m struct {
		Session string `json:"session"`
		Kind    string `json:"kind"`
	}
	if err := json.Unmarshal(payload, &m); err != nil || !proto.ValidSessionID(m.Session) {
		return
	}

	arrivalPort := ln.LocalAddr().(*net.UDPAddr).Port
	max := s.cfg.MaxUDP
	if proto.UDPKind(m.Kind) == proto.UDPPMTU {
		max = s.cfg.MaxUDPPMTU
	}
	if len(payload) > max {
		return // oversized: drop silently (THR-PROBE-001)
	}

	var replier *net.UDPConn
	var replyFrom string
	switch proto.UDPKind(m.Kind) {
	case proto.UDPEcho, proto.UDPReach, proto.UDPPMTU:
		replier, replyFrom = ln, "same"
	case proto.UDPNat:
		replier = s.natLn
		switch {
		case s.cfg.SecondIP != "":
			replyFrom = "other-ip"
		case replier.LocalAddr().(*net.UDPAddr).Port != arrivalPort:
			replyFrom = "other-port"
		default:
			replyFrom = "same"
		}
	default:
		return
	}

	s.recordUDP(m.Session, src, ttl, m.Kind, replyFrom, len(payload), arrivalPort)
	_, _ = replier.WriteToUDP(payload, src)
}

func (s *Server) recordUDP(session string, src *net.UDPAddr, ttl int, kind, replyFrom string, payloadLen, dstPort int) {
	obs := &proto.Obs{
		ID:      proto.NewID(),
		Kind:    proto.ObsUDP,
		Session: session,
		SrcIP:   src.IP.String(),
		SrcPort: src.Port,
		DstPort: dstPort,
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
