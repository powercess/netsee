// Package client implements the netsee client: local collection,
// probe session, NAT/PMTU/DNS/reputation measurements and the TUN
// attribution layer.
package client

import "time"

// Note is a single honest-context remark attached to a result.
type Note struct {
	Level string `json:"level"` // "info" | "warn" | "error"
	Text  string `json:"text"`
}

// Result is the complete set of facts and judgments for one measurement.
// P3 renders this into the text/JSON report; here it is the structured
// contract between the client and the report layer.
type Result struct {
	Session     string            `json:"session"`
	Started     time.Time         `json:"started"`
	Duration    time.Duration     `json:"duration"`
	Local       LocalInfo         `json:"local"`
	Attribution Attribution       `json:"attribution"`
	PublicIPs   []string          `json:"public_ips"`
	Probe       ProbeResult       `json:"probe"`
	NAT         *NATResult        `json:"nat,omitempty"`
	PMTU        *PMTUResult       `json:"pmtu,omitempty"`
	DNS         *DNSResult        `json:"dns,omitempty"`
	Reputation  *ReputationResult `json:"reputation,omitempty"`
	Direct      *Result           `json:"direct,omitempty"`
	Notes       []Note            `json:"notes"`
}

func (r *Result) addNote(level, text string) {
	r.Notes = append(r.Notes, Note{Level: level, Text: text})
}

// ProbeResult records the probe-side facts for the session.
type ProbeResult struct {
	ProbeURL     string        `json:"probe_url"`
	ProtocolVer  string        `json:"protocol_version"`
	Info         *Info         `json:"info"`
	Observations []Observation `json:"observations"`
	ExitIPs      []string      `json:"exit_ips"` // probe-observed src IPs
	Connectivity []PortCheck   `json:"connectivity"`
}

// Info is the port self-discovery response (mirrors proto.Info).
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

// Observation is one probe-side fact about a connection.
type Observation struct {
	Kind      string `json:"kind"` // http | tcp | udp | tls
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	JA3       string `json:"ja3,omitempty"`
	JA4       string `json:"ja4,omitempty"`
	SNI       string `json:"sni,omitempty"`
	MSS       uint32 `json:"mss,omitempty"`
	ReplyFrom string `json:"reply_from,omitempty"`
}

// PortCheck is one client-side connectivity attempt with the probe-side
// confirmation (防误判: 客户端尝试 + 探针回报比对).
type PortCheck struct {
	Port       int    `json:"port"`
	Proto      string `json:"proto"`      // tcp | udp
	Connected  bool   `json:"connected"`  // client reached the port
	ProbeSaw   bool   `json:"probe_saw"`  // probe recorded an observation
	Consistent bool   `json:"consistent"` // connected == probe_saw
}
