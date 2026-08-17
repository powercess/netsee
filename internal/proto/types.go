// Package proto defines the shared types between the netsee client and
// probe. It is the single source of truth for the session protocol;
// both sides MUST NOT maintain drifting copies (see docs/protocol/probe.md).
package proto

import "time"

// ObsKind identifies the transport/observation type.
type ObsKind string

const (
	ObsHTTP ObsKind = "http"
	ObsTCP  ObsKind = "tcp"
	ObsUDP  ObsKind = "udp"
	ObsTLS  ObsKind = "tls"
)

// UDPKind is the kind field carried in UDP payloads.
type UDPKind string

const (
	UDPEcho  UDPKind = "echo"
	UDPNat   UDPKind = "nat"
	UDPReach UDPKind = "reach"
	UDPPMTU  UDPKind = "pmtu"
)

// Header is a single HTTP request header as observed by the probe.
type Header struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// HTTPObs is the server-side view of an HTTP request.
type HTTPObs struct {
	Method  string   `json:"method"`
	Path    string   `json:"path"`
	Proto   string   `json:"proto"`
	Headers []Header `json:"headers"`
}

// TCPInfo is the TCP_INFO peer fingerprint as seen by the probe
// (MSS/WScale/SACK/TS/ECN negotiated options + smoothed RTT).
type TCPInfo struct {
	MSS    uint32 `json:"mss"`
	WScale bool   `json:"wscale"`
	SACK   bool   `json:"sack"`
	TS     bool   `json:"ts"`
	ECN    bool   `json:"ecn"`
	RTTUs  uint32 `json:"rtt_us"`
}

// TLSFingerprint is derived from the ClientHello.
type TLSFingerprint struct {
	JA3 string `json:"ja3"`
	JA4 string `json:"ja4"`
	SNI string `json:"sni"`
}

// UDPObs records a UDP exchange.
type UDPObs struct {
	Kind       string `json:"kind"`
	ReplyFrom  string `json:"reply_from"` // "same" | "other-port" | "other-ip"
	PayloadLen int    `json:"payload_len"`
}

// Obs is one observation recorded by the probe: the remote view of a
// single connection or datagram belonging to a session.
type Obs struct {
	ID      string          `json:"id"`
	Kind    ObsKind         `json:"kind"`
	Session string          `json:"session"`
	SrcIP   string          `json:"src_ip"`
	SrcPort int             `json:"src_port"`
	DstPort int             `json:"dst_port"`
	TTL     int             `json:"ttl,omitempty"`
	Time    time.Time       `json:"time"`
	HTTP    *HTTPObs        `json:"http,omitempty"`
	TCPInfo *TCPInfo        `json:"tcp_info,omitempty"`
	TLS     *TLSFingerprint `json:"tls,omitempty"`
	UDP     *UDPObs         `json:"udp,omitempty"`
}

// Info is the GET /api/info response: port self-discovery so the client
// needs zero configuration.
type Info struct {
	ProtocolVersion string `json:"protocol_version"`
	HTTPPort        int    `json:"http_port"`
	TLSPort         int    `json:"tls_port"`
	UDPPort         int    `json:"udp_port"`
	NATPort         int    `json:"nat_port"`
	ExtraPorts      []int  `json:"extra_ports"`
	SecondIP        bool   `json:"second_ip"`
	SecondIPAddr    string `json:"second_ip_addr,omitempty"`
	MaxUDPPMTU      int    `json:"max_udp_pmtu"`
}
