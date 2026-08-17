package client

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"netsee/internal/proto"
)

// NATFact is one raw observation feeding the NAT judgment.
type NATFact struct {
	Kind        string `json:"kind"` // mapping | filter
	Detail      string `json:"detail"`
	ObservedSrc string `json:"observed_src"` // probe-seen ip:port
	ReplyFrom   string `json:"reply_from"`
	Received    bool   `json:"received"`
}

// NATResult is the NAT classification with raw facts, label, premise and
// confidence (facts always precede the label, per the baseline).
type NATResult struct {
	Facts            []NATFact `json:"facts"`
	Label            string    `json:"label"`
	Premise          string    `json:"premise,omitempty"`
	Confidence       string    `json:"confidence"`
	EchoReceived     bool      `json:"-"` // reply from same port received
	NATReplyReceived bool      `json:"-"` // reply from other port received
}

// RunNAT performs the NAT mapping and filtering tests through the probe.
func (s *Session) RunNAT(ctx context.Context, timeout time.Duration) (*NATResult, error) {
	res := &NATResult{}
	host := hostOf(s.probe)
	localIP := ""

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0")})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// The measurement socket is unconnected (so it can receive replies
	// from any source port for the filter test). Derive the source IP it
	// will use towards the probe from a throwaway connected socket.
	probeAddr := &net.UDPAddr{IP: net.ParseIP(host), Port: s.info.UDPPort}
	if pc, err := net.DialUDP("udp", nil, probeAddr); err == nil {
		localIP = pc.LocalAddr().(*net.UDPAddr).IP.String()
		pc.Close()
	}

	// send delivers one datagram to probe:port, waits briefly for a reply
	// (filter test) and returns the probe-observed source address.
	send := func(port int, kind, payload string) (srcIP string, srcPort int, replyFrom string, received bool, err error) {
		addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
		if _, err := conn.WriteToUDP([]byte(payload), addr); err != nil {
			return "", 0, "", false, err
		}
		buf := make([]byte, 65535)
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		if _, _, rerr := conn.ReadFromUDP(buf); rerr == nil {
			received = true
		}
		obs, err := s.Pull(ctx)
		if err != nil {
			return "", 0, "", received, err
		}
		for i := len(obs) - 1; i >= 0; i-- {
			o := obs[i]
			if o.Kind == proto.ObsUDP && o.DstPort == port && o.UDP != nil && o.UDP.Kind == kind {
				return o.SrcIP, o.SrcPort, o.UDP.ReplyFrom, received, nil
			}
		}
		return "", 0, "", received, fmt.Errorf("no probe observation for %s to port %d", kind, port)
	}

	echo := fmt.Sprintf(`{"session":"%s","kind":"echo"}`, s.id)
	nat := fmt.Sprintf(`{"session":"%s","kind":"nat"}`, s.id)

	// Mapping stability: same socket, same destination, twice.
	ip1, p1, rf1, r1, err := send(s.info.UDPPort, "echo", echo)
	if err != nil {
		return nil, err
	}
	res.EchoReceived = r1
	ip1b, p1b, rf1b, r1b, err := send(s.info.UDPPort, "echo", echo)
	if err != nil {
		return nil, err
	}
	res.Facts = append(res.Facts,
		NATFact{Kind: "mapping", Detail: "echo → udp 端口（首次）", ObservedSrc: net.JoinHostPort(ip1, strconv.Itoa(p1)), ReplyFrom: rf1, Received: r1},
		NATFact{Kind: "mapping", Detail: "echo → udp 端口（同 socket 再次）", ObservedSrc: net.JoinHostPort(ip1b, strconv.Itoa(p1b)), ReplyFrom: rf1b, Received: r1b},
	)

	// Symmetric check: same socket, different destination (nat port).
	ip2, p2, rf2, r2, err := send(s.info.NATPort, "echo", echo)
	if err != nil {
		return nil, err
	}
	res.Facts = append(res.Facts,
		NATFact{Kind: "mapping", Detail: "echo → nat 端口（不同目标）", ObservedSrc: net.JoinHostPort(ip2, strconv.Itoa(p2)), ReplyFrom: rf2, Received: r2},
	)

	// Port filter: reply from a different port.
	ip3, p3, rf3, r3, err := send(s.info.UDPPort, "nat", nat)
	if err != nil {
		return nil, err
	}
	res.NATReplyReceived = r3
	res.Facts = append(res.Facts,
		NATFact{Kind: "filter", Detail: "nat → udp 端口，回包来自异端口", ObservedSrc: net.JoinHostPort(ip3, strconv.Itoa(p3)), ReplyFrom: rf3, Received: r3},
	)

	// IP filter (only when the probe has a second IP).
	r4 := false
	if s.info.SecondIP {
		_, _, rf4, r4, err := send(s.info.UDPPort, "nat", nat)
		if err != nil {
			return nil, err
		}
		res.Facts = append(res.Facts,
			NATFact{Kind: "filter", Detail: "nat → udp 端口，回包来自异 IP（second-ip）", ReplyFrom: rf4, Received: r4},
		)
	}

	res.Confidence = "中"
	res.Premise = "单 IP 探针无法区分全锥 vs 受限锥、对称 vs 端口依赖映射（需第二 IP 做完整 RFC 5780 分类）"

	// Judgment: raw facts first, then label.
	observedIP := ip1
	sameSocketPort := p1 == p2
	switch {
	case observedIP == localIP:
		res.Label = "直连（无 NAT 翻译）"
		res.Confidence = "高（探针观测源 IP 与本机一致）"
		res.Premise = ""
	case sameSocketPort:
		res.Label = "对称式映射"
	case r3:
		res.Label = "锥形（端口不过滤）"
		if s.info.SecondIP && !r4 {
			res.Label = "地址受限锥形"
		}
	default:
		res.Label = "端口受限锥形"
	}
	return res, nil
}
