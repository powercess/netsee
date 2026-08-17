package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// PMTUFact is one payload-size probe in the path-MTU binary search.
type PMTUFact struct {
	Size int  `json:"size"`
	OK   bool `json:"ok"` // sent without EMSGSIZE
}

// PMTUResult is the estimated path MTU with raw facts.
type PMTUResult struct {
	Facts     []PMTUFact `json:"facts"`
	PathMTU   int        `json:"path_mtu"` // estimated (0 = unknown)
	Blackhole bool       `json:"blackhole"`
	Note      string     `json:"note,omitempty"`
}

// RunPMTU estimates the path MTU to the probe using IP_PMTUDISC_DO
// (DF bit): sendto returns EMSGSIZE when the datagram exceeds the path
// MTU. The probe echoes pmtu-kind payloads so we can confirm reachability
// and detect a silent PMTU blackhole (send succeeds, no reply).
func (s *Session) RunPMTU(ctx context.Context, timeout time.Duration) (*PMTUResult, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0")})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := setPMTUDiscDo(conn); err != nil {
		return &PMTUResult{Note: "IP_PMTUDISC 设置失败: " + err.Error()}, nil
	}

	cap := s.info.MaxUDPPMTU
	if cap <= 0 || cap > 9000 {
		cap = 9000
	}
	host := hostOf(s.probe)
	dst := &net.UDPAddr{IP: net.ParseIP(host), Port: s.info.UDPPort}

	res := &PMTUResult{}
	// The payload must stay valid JSON so the probe parses session/kind:
	// padding goes inside a data string field.
	head := fmt.Sprintf(`{"session":"%s","kind":"pmtu","data":"`, s.id)
	tail := `"}`
	minSize := len(head) + len(tail) + 1
	payload := func(size int) []byte {
		b := make([]byte, size)
		copy(b, head)
		for i := len(head); i < size-len(tail); i++ {
			b[i] = 'a'
		}
		copy(b[size-len(tail):], tail)
		return b
	}

	// Binary search the largest size that sends without EMSGSIZE.
	lo, hi := minSize, cap
	lastOK := 0
	for lo <= hi {
		mid := (lo + hi) / 2
		_, werr := conn.WriteToUDP(payload(mid), dst)
		if werr != nil && !errors.Is(werr, syscall.EMSGSIZE) {
			return nil, werr
		}
		ok := werr == nil
		res.Facts = append(res.Facts, PMTUFact{Size: mid, OK: ok})
		if ok {
			lastOK = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}

	// Blackhole check: the largest OK size must be echoed back. A send
	// that succeeds (≤ path MTU) but gets no reply suggests a PMTU
	// blackhole (DF fragments silently dropped mid-path).
	if lastOK > 0 {
		if _, werr := conn.WriteToUDP(payload(lastOK), dst); werr == nil {
			_ = conn.SetReadDeadline(time.Now().Add(timeout))
			rbuf := make([]byte, cap+64)
			if _, _, rerr := conn.ReadFromUDP(rbuf); rerr != nil {
				res.Blackhole = true
			}
		}
	}

	if lastOK > 0 {
		res.PathMTU = lastOK + 28 // IPv4: 20 IP + 8 UDP headers
	}
	if lastOK >= cap {
		res.Note = fmt.Sprintf("达到探针 pmtu 载荷上限 %d，实际路径 MTU 可能更大", cap)
	}
	return res, nil
}
