package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"netsee/internal/client"
	"netsee/internal/proto"
)

func fixtureResult() *client.Result {
	return &client.Result{
		Session:   "01234567-89ab-cdef-0123-456789abcdef",
		Started:   time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC),
		Duration:  3 * time.Second,
		PublicIPs: []string{"203.0.113.7"},
		Local: client.LocalInfo{
			DefaultRouteV4: "tun0",
			DefaultGWV4:    "10.1.1.1",
			DefaultMTU:     1500,
			Interfaces:     []client.InterfaceInfo{{Name: "tun0", MTU: 1500}},
			ResolvConf:     &client.ResolvConf{Nameservers: []string{"198.18.0.1", "8.8.8.8"}},
		},
		Attribution: client.Attribution{
			TUN:          true,
			TUNInterface: "tun0",
			FakeIP:       true,
			FakeIPNote:   "系统解析器指向 fake-ip 段（198.18.0.0/15）",
			UDP:          "tun-blocked",
			Note:         "流量经 TUN 接管，探针观测为代理出口（程序未知，不点名）",
		},
		Probe: client.ProbeResult{
			ProtocolVer: "1",
			ExitIPs:     []string{"203.0.113.7"},
			Observations: []client.Observation{
				{
					Kind: "http", SrcIP: "203.0.113.7", SrcPort: 51234, DstPort: 8080,
					MSS: 1460, WScale: true, SACK: true, TS: true, RTTUs: 12000,
					HTTPMethod: "GET", HTTPPath: "/echo",
					HTTPHeaders: []proto.Header{
						{Key: "Host", Value: "203.0.113.7"},
						{Key: "X-Forwarded-For", Value: "10.0.0.5"},
						{Key: "Via", Value: "1.1 proxy"},
					},
					HTTPTraces: []string{"X-Forwarded-For: 10.0.0.5", "Via: 1.1 proxy"},
				},
				{
					Kind: "tls", SrcIP: "203.0.113.7", SrcPort: 51235, DstPort: 8443,
					JA3: "9b7dcdf3f997f1fb7b4409c94cb7ef36",
					JA4: "t12d270800_a2460661a67a_36cef8aed422",
					SNI: "01234567-89ab-cdef-0123-456789abcdef.1",
				},
				{Kind: "udp", SrcIP: "203.0.113.7", SrcPort: 51236, DstPort: 8444, ReplyFrom: "same"},
			},
			Connectivity: []client.PortCheck{{Port: 8080, Proto: "tcp", Connected: true, ProbeSaw: true, Consistent: true}},
		},
		NAT: &client.NATResult{
			Facts: []client.NATFact{
				{Kind: "mapping", Detail: "echo → udp 端口（首次）", ObservedSrc: "203.0.113.7:51236", ReplyFrom: "same", Received: true},
				{Kind: "mapping", Detail: "echo → nat 端口（不同目标）", ObservedSrc: "203.0.113.7:51237", ReplyFrom: "same", Received: true},
			},
			Label:      "对称式映射",
			Premise:    "单 IP 探针无法区分对称 vs 端口依赖映射",
			Confidence: "中",
		},
		PMTU: &client.PMTUResult{PathMTU: 1500, Facts: []client.PMTUFact{{Size: 1472, OK: true}}},
		DNS: &client.DNSResult{
			Host: "example.com", SystemAnswers: []string{"93.184.216.34"},
			DoHAnswers: []string{"93.184.216.34"}, DoHStatus: "ok", Same: true,
			Judgment: "一致（未检测到劫持）",
		},
		Reputation: &client.ReputationResult{
			IP: "203.0.113.7", Country: "US", Region: "CA", City: "San Francisco",
			ISP: "Example ISP", AS: "AS12345", Source: "ip-api",
		},
		Notes: []client.Note{{Level: "info", Text: "沿途节点有能力看到以下信息"}},
	}
}

func TestBuildStructure(t *testing.T) {
	rep := Build(fixtureResult())

	if rep.HonestContext != honestContext {
		t.Errorf("honest context = %q", rep.HonestContext)
	}
	if len(rep.Overview.PublicIPs) != 1 || rep.Overview.ExitCount != 1 {
		t.Errorf("overview = %+v", rep.Overview)
	}
	if rep.Overview.NATType != "对称式映射" {
		t.Errorf("NATType = %q", rep.Overview.NATType)
	}
	if rep.Overview.RTTMs != 12.0 {
		t.Errorf("RTTMs = %v, want 12", rep.Overview.RTTMs)
	}
	if len(rep.Overview.Highlights) == 0 {
		t.Error("no highlights")
	}
	for _, h := range rep.Overview.Highlights {
		if strings.Contains(h, "DNS 疑似劫持") {
			t.Errorf("false hijack highlight for consistent DNS: %q", h)
		}
	}

	// Facts precede the label.
	if rep.NAT == nil || len(rep.NAT.Facts) == 0 || rep.NAT.Label != "对称式映射" {
		t.Errorf("NAT item = %+v", rep.NAT)
	}
	if rep.NAT.Layer != "exit" {
		t.Errorf("NAT layer = %q, want exit", rep.NAT.Layer)
	}

	if rep.TCP == nil || rep.TCP.MSS != 1460 || !rep.TCP.WScale {
		t.Errorf("TCP = %+v", rep.TCP)
	}
	if rep.TCP.Layer != "end" {
		t.Errorf("TCP layer = %q", rep.TCP.Layer)
	}
	if rep.TLS == nil || rep.TLS.JA3 != "9b7dcdf3f997f1fb7b4409c94cb7ef36" {
		t.Errorf("TLS = %+v", rep.TLS)
	}
	if rep.HTTP == nil || len(rep.HTTP.Traces) != 2 {
		t.Errorf("HTTP traces = %+v", rep.HTTP)
	}
	if rep.MTU == nil || rep.MTU.PathMTU != 1500 {
		t.Errorf("MTU = %+v", rep.MTU)
	}
	if rep.DNS == nil || rep.DNS.Judgment != "一致（未检测到劫持）" {
		t.Errorf("DNS = %+v", rep.DNS)
	}
	if rep.Reputation == nil || rep.Reputation.Country != "US" {
		t.Errorf("Reputation = %+v", rep.Reputation)
	}
	if !rep.Local.TUN || !rep.Local.FakeIP || rep.Local.UDP != "tun-blocked" {
		t.Errorf("Local attribution = %+v", rep.Local)
	}
}

func TestRenderTextSections(t *testing.T) {
	var buf bytes.Buffer
	Build(fixtureResult()).RenderText(&buf)
	s := buf.String()

	for _, want := range []string{
		"诚实上下文",
		honestContext,
		"一、概览",
		"二、本机网络",
		"三、出口层 — NAT 判定",
		"四、对方视角总表",
		"五、终点层 — TCP 指纹",
		"六、终点层 — TLS 指纹",
		"七、终点层 — HTTP 视角",
		"八、端口连通性",
		"九、路径层 — 路径 MTU",
		"十、路径层 — DNS",
		"十一、出口层 — IP 信誉",
		"对称式映射",
		"mss=1460",
		"ja3=9b7dcdf3f997f1fb7b4409c94cb7ef36",
		"X-Forwarded-For: 10.0.0.5",
		"tun0",
		"TUN 接管",
		"探针 UDP NAT 回包",
		"观测点",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("text missing %q", want)
		}
	}
	// Facts must appear before the judgment label in the NAT section.
	natSection := s[strings.Index(s, "三、出口层 — NAT 判定"):]
	if strings.Index(natSection, "原始事实") > strings.Index(natSection, "判定: 对称式映射") {
		t.Error("facts do not precede judgment in NAT section")
	}
}

func TestJSONFieldParity(t *testing.T) {
	rep := Build(fixtureResult())
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{
		"session", "honest_context", "overview", "local", "nat",
		"observations", "tcp", "tls", "http", "ports", "mtu", "dns", "reputation", "notes",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("JSON missing key %q", key)
		}
	}
	// The same values must be present in the text output (field parity).
	var buf bytes.Buffer
	rep.RenderText(&buf)
	text := buf.String()
	checks := []string{
		rep.HonestContext,
		rep.Overview.NATType,
		rep.NAT.Label,
		rep.TLS.JA3,
		rep.MTU.PathMTUStr(),
		rep.DNS.Judgment,
	}
	for _, c := range checks {
		if c != "" && !strings.Contains(text, c) {
			t.Errorf("text missing value %q", c)
		}
	}
}

func TestDirectSubreport(t *testing.T) {
	fixture := fixtureResult()
	direct := fixtureResult()
	direct.PublicIPs = []string{"192.0.2.9"}
	direct.NAT = &client.NATResult{Label: "端口受限锥形", Facts: []client.NATFact{{Detail: "x", ObservedSrc: "192.0.2.9:1", Received: true}}}
	fixture.Direct = direct

	rep := Build(fixture)
	if rep.Direct == nil {
		t.Fatal("direct subreport missing")
	}
	if rep.Direct.Overview.PublicIPs[0] != "192.0.2.9" {
		t.Errorf("direct public IP = %v", rep.Direct.Overview.PublicIPs)
	}
	var buf bytes.Buffer
	rep.RenderText(&buf)
	if !strings.Contains(buf.String(), "十二、直连对比") {
		t.Error("direct comparison section missing from text")
	}
	if !strings.Contains(buf.String(), "192.0.2.9") {
		t.Error("direct IP missing from comparison table")
	}
}
