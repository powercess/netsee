// Package report renders a netsee client.Result into the final report: a
// three-layer (exit / path middlebox / destination) structured view with
// the fixed honest-context line. The Report struct is the single schema
// shared by the text and JSON renderers, so both outputs always cover the
// same fields (ACC-P3-002). Raw facts always precede judgment labels
// (ACC-P3-003).
package report

import (
	"strings"
	"time"

	"netsee/internal/client"
	"netsee/internal/proto"
)

// honestContext is the fixed honesty line required by the baseline.
const honestContext = "沿途节点有能力看到以下信息；是否真的在看取决于具体服务商。本工具测的是暴露面，不是实际被监视。"

// Report is the rendered report. Field order = mandated reading order:
// 概览 → 本机网络 → NAT → 对方视角总表 → TCP → TLS → HTTP → 端口 → MTU →
// DNS → 信誉 → 备注 → 直连对比.
type Report struct {
	Session       string               `json:"session"`
	Generated     string               `json:"generated"`
	DurationSec   float64              `json:"duration_sec"`
	HonestContext string               `json:"honest_context"`
	Overview      Overview             `json:"overview"`
	Local         Local                `json:"local"`
	NAT           *NATItem             `json:"nat,omitempty"`
	Observations  []client.Observation `json:"observations"`
	TCP           *TCPItem             `json:"tcp,omitempty"`
	TLS           *TLSItem             `json:"tls,omitempty"`
	HTTP          *HTTPItem            `json:"http,omitempty"`
	Ports         []client.PortCheck   `json:"ports"`
	MTU           *MTUItem             `json:"mtu,omitempty"`
	DNS           *DNSItem             `json:"dns,omitempty"`
	Reputation    *ReputationItem      `json:"reputation,omitempty"`
	Notes         []client.Note        `json:"notes"`
	Direct        *Report              `json:"direct,omitempty"`
}

// ItemMeta tags each detection item with its layer and observation point.
type ItemMeta struct {
	Layer      string `json:"layer"`       // exit | path | end
	ObservedBy string `json:"observed_by"` // 观测点
}

// Overview is the executive summary.
type Overview struct {
	PublicIPs  []string `json:"public_ips"`
	ExitCount  int      `json:"exit_count"`
	NATType    string   `json:"nat_type,omitempty"`
	RTTMs      float64  `json:"rtt_ms,omitempty"`
	Highlights []string `json:"highlights"`
}

// Local is the local-network section with path attribution.
type Local struct {
	DefaultRouteV4 string   `json:"default_route_v4,omitempty"`
	DefaultGWV4    string   `json:"default_gw_v4,omitempty"`
	DefaultRouteV6 string   `json:"default_route_v6,omitempty"`
	MTU            int      `json:"mtu"`
	Interfaces     int      `json:"interfaces"`
	Nameservers    []string `json:"nameservers,omitempty"`
	TUN            bool     `json:"tun"`
	TUNInterface   string   `json:"tun_interface,omitempty"`
	FakeIP         bool     `json:"fake_ip"`
	FakeIPNote     string   `json:"fake_ip_note,omitempty"`
	ProxyStack     string   `json:"proxy_stack,omitempty"`
	UDP            string   `json:"udp,omitempty"`
	Note           string   `json:"note,omitempty"`
}

// NATItem carries raw facts before the label (ACC-P3-003).
type NATItem struct {
	ItemMeta
	Facts      []client.NATFact `json:"facts"`
	Label      string           `json:"label"`
	Premise    string           `json:"premise,omitempty"`
	Confidence string           `json:"confidence"`
}

type TCPItem struct {
	ItemMeta
	MSS    uint32  `json:"mss,omitempty"`
	WScale bool    `json:"wscale,omitempty"`
	SACK   bool    `json:"sack,omitempty"`
	TS     bool    `json:"ts,omitempty"`
	ECN    bool    `json:"ecn,omitempty"`
	RTTMs  float64 `json:"rtt_ms,omitempty"`
}

type TLSItem struct {
	ItemMeta
	JA3 string `json:"ja3,omitempty"`
	JA4 string `json:"ja4,omitempty"`
	SNI string `json:"sni,omitempty"`
}

type HTTPItem struct {
	ItemMeta
	Method  string         `json:"method,omitempty"`
	Path    string         `json:"path,omitempty"`
	Headers []proto.Header `json:"headers,omitempty"`
	Traces  []string       `json:"traces,omitempty"`
}

type MTUItem struct {
	ItemMeta
	PathMTU   int    `json:"path_mtu"`
	Blackhole bool   `json:"blackhole"`
	Note      string `json:"note,omitempty"`
}

type DNSItem struct {
	ItemMeta
	Host          string   `json:"host"`
	SystemAnswers []string `json:"system_answers"`
	DoHAnswers    []string `json:"doh_answers"`
	DoHStatus     string   `json:"doh_status"`
	Judgment      string   `json:"judgment"`
	Premise       string   `json:"premise,omitempty"`
}

type ReputationItem struct {
	ItemMeta
	Country string `json:"country,omitempty"`
	Region  string `json:"region,omitempty"`
	City    string `json:"city,omitempty"`
	ISP     string `json:"isp,omitempty"`
	AS      string `json:"as,omitempty"`
	Proxy   bool   `json:"proxy"`
	Hosting bool   `json:"hosting"`
	Source  string `json:"source"`
	Note    string `json:"note,omitempty"`
}

// Build derives the Report from a measurement Result.
func Build(r *client.Result) *Report {
	rep := &Report{
		Session:       r.Session,
		Generated:     r.Started.Format(time.RFC3339),
		DurationSec:   r.Duration.Seconds(),
		HonestContext: honestContext,
		Overview:      buildOverview(r),
		Local:         buildLocal(r),
		Observations:  r.Probe.Observations,
		Ports:         r.Probe.Connectivity,
		Notes:         r.Notes,
	}
	rep.NAT = buildNAT(r)
	rep.TCP = buildTCP(r)
	rep.TLS = buildTLS(r)
	rep.HTTP = buildHTTP(r)
	rep.MTU = buildMTU(r)
	rep.DNS = buildDNS(r)
	rep.Reputation = buildReputation(r)
	if r.Direct != nil {
		rep.Direct = Build(r.Direct)
	}
	return rep
}

func buildOverview(r *client.Result) Overview {
	ov := Overview{PublicIPs: r.PublicIPs, ExitCount: len(r.PublicIPs)}
	if r.NAT != nil {
		ov.NATType = r.NAT.Label
	}
	for _, o := range r.Probe.Observations {
		if o.RTTUs > 0 {
			ov.RTTMs = float64(o.RTTUs) / 1000
			break
		}
	}
	ov.Highlights = highlights(r)
	return ov
}

func highlights(r *client.Result) []string {
	var h []string
	a := r.Attribution
	if a.TUN {
		h = append(h, "流量经 TUN 接管，探针观测为代理出口（非本机直连）")
	}
	if a.FakeIP {
		h = append(h, "DNS 被代理接管（fake-ip）")
	}
	if a.ProxyStack != nil {
		h = append(h, "代理栈: "+a.ProxyStack.Name)
	}
	if a.UDP == "tun-blocked" {
		h = append(h, "UDP 未被代理转发")
	}
	if len(r.PublicIPs) > 1 {
		h = append(h, "多个公网出口 IP（v4/v6 或多路径）")
	}
	if r.NAT != nil {
		switch r.NAT.Label {
		case "对称式映射":
			h = append(h, "对称式 NAT 映射")
		case "端口受限锥形":
			h = append(h, "端口受限锥形 NAT")
		}
	}
	if r.PMTU != nil && r.PMTU.Blackhole {
		h = append(h, "疑似 PMTU 黑洞")
	}
	if r.DNS != nil && strings.Contains(r.DNS.Judgment, "疑似") && !a.FakeIP {
		h = append(h, "DNS 疑似劫持/分流（低置信度）")
	}
	if r.Reputation != nil && r.Reputation.Proxy {
		h = append(h, "出口 IP 标记为代理/机房")
	}
	if len(h) == 0 {
		h = append(h, "未发现显著异常")
	}
	return h
}

func buildLocal(r *client.Result) Local {
	l := r.Local
	out := Local{
		DefaultRouteV4: l.DefaultRouteV4,
		DefaultGWV4:    l.DefaultGWV4,
		DefaultRouteV6: l.DefaultRouteV6,
		MTU:            l.DefaultMTU,
		Interfaces:     len(l.Interfaces),
	}
	if l.ResolvConf != nil {
		out.Nameservers = l.ResolvConf.Nameservers
	}
	a := r.Attribution
	out.TUN, out.TUNInterface = a.TUN, a.TUNInterface
	out.FakeIP, out.FakeIPNote = a.FakeIP, a.FakeIPNote
	if a.ProxyStack != nil {
		out.ProxyStack = a.ProxyStack.Name
	}
	out.UDP, out.Note = a.UDP, a.Note
	return out
}

func buildNAT(r *client.Result) *NATItem {
	if r.NAT == nil {
		return nil
	}
	return &NATItem{
		ItemMeta:   ItemMeta{Layer: "exit", ObservedBy: "探针 UDP NAT 回包"},
		Facts:      r.NAT.Facts,
		Label:      r.NAT.Label,
		Premise:    r.NAT.Premise,
		Confidence: r.NAT.Confidence,
	}
}

func buildTCP(r *client.Result) *TCPItem {
	for _, o := range r.Probe.Observations {
		if o.MSS == 0 {
			continue
		}
		return &TCPItem{
			ItemMeta: ItemMeta{Layer: "end", ObservedBy: "探针 TCP_INFO"},
			MSS:      o.MSS,
			WScale:   o.WScale,
			SACK:     o.SACK,
			TS:       o.TS,
			ECN:      o.ECN,
			RTTMs:    float64(o.RTTUs) / 1000,
		}
	}
	return nil
}

func buildTLS(r *client.Result) *TLSItem {
	for _, o := range r.Probe.Observations {
		if o.JA3 == "" {
			continue
		}
		return &TLSItem{
			ItemMeta: ItemMeta{Layer: "end", ObservedBy: "探针 TLS 嗅探"},
			JA3:      o.JA3,
			JA4:      o.JA4,
			SNI:      o.SNI,
		}
	}
	return nil
}

func buildHTTP(r *client.Result) *HTTPItem {
	for _, o := range r.Probe.Observations {
		if o.HTTPMethod == "" {
			continue
		}
		return &HTTPItem{
			ItemMeta: ItemMeta{Layer: "end", ObservedBy: "探针 HTTP echo"},
			Method:   o.HTTPMethod,
			Path:     o.HTTPPath,
			Headers:  o.HTTPHeaders,
			Traces:   o.HTTPTraces,
		}
	}
	return nil
}

func buildMTU(r *client.Result) *MTUItem {
	if r.PMTU == nil {
		return nil
	}
	return &MTUItem{
		ItemMeta:  ItemMeta{Layer: "path", ObservedBy: "探针 UDP pmtu"},
		PathMTU:   r.PMTU.PathMTU,
		Blackhole: r.PMTU.Blackhole,
		Note:      r.PMTU.Note,
	}
}

func buildDNS(r *client.Result) *DNSItem {
	if r.DNS == nil {
		return nil
	}
	return &DNSItem{
		ItemMeta:      ItemMeta{Layer: "path", ObservedBy: "系统解析器 + DoH"},
		Host:          r.DNS.Host,
		SystemAnswers: r.DNS.SystemAnswers,
		DoHAnswers:    r.DNS.DoHAnswers,
		DoHStatus:     r.DNS.DoHStatus,
		Judgment:      r.DNS.Judgment,
		Premise:       r.DNS.Premise,
	}
}

func buildReputation(r *client.Result) *ReputationItem {
	if r.Reputation == nil {
		return nil
	}
	return &ReputationItem{
		ItemMeta: ItemMeta{Layer: "exit", ObservedBy: "外部 IP 信誉库（ip-api/ipinfo）"},
		Country:  r.Reputation.Country,
		Region:   r.Reputation.Region,
		City:     r.Reputation.City,
		ISP:      r.Reputation.ISP,
		AS:       r.Reputation.AS,
		Proxy:    r.Reputation.Proxy,
		Hosting:  r.Reputation.Hosting,
		Source:   r.Reputation.Source,
		Note:     r.Reputation.Note,
	}
}
