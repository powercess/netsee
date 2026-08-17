package report

import (
	"fmt"
	"io"
	"strings"
)

// RenderText writes the report in the mandated reading order. It walks
// the same Report struct as the JSON renderer, so the two always cover
// identical fields (ACC-P3-002).
func (rep *Report) RenderText(w io.Writer) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }

	p("NetSee 网络暴露面检测报告")
	p("会话 %s · %s · 耗时 %.1fs", shortID(rep.Session), rep.Generated, rep.DurationSec)
	p("")
	p("诚实上下文: %s", rep.HonestContext)
	p("")

	p("一、概览")
	p("  公网出口 IP: %s", joinOrNA(rep.Overview.PublicIPs))
	p("  出口数: %d", rep.Overview.ExitCount)
	if rep.Overview.NATType != "" {
		p("  NAT 类型: %s", rep.Overview.NATType)
	}
	if rep.Overview.RTTMs > 0 {
		p("  探针侧 RTT: %.2f ms", rep.Overview.RTTMs)
	}
	p("  突出发现:")
	for _, h := range rep.Overview.Highlights {
		p("    - %s", h)
	}
	p("")

	p("二、本机网络")
	p("  默认路由: %s (MTU %d) 网关 %s", orNA(rep.Local.DefaultRouteV4), rep.Local.MTU, orNA(rep.Local.DefaultGWV4))
	if rep.Local.DefaultRouteV6 != "" {
		p("  IPv6 默认路由: %s", rep.Local.DefaultRouteV6)
	}
	p("  接口: %d", rep.Local.Interfaces)
	if len(rep.Local.Nameservers) > 0 {
		p("  DNS 解析器: %s", strings.Join(rep.Local.Nameservers, ", "))
	}
	renderAttribution(p, rep.Local)
	p("")

	if rep.NAT != nil {
		p("三、出口层 — NAT 判定 [观测点: %s]", rep.NAT.ObservedBy)
		p("  原始事实:")
		for _, f := range rep.NAT.Facts {
			p("    - %s: 探针观测 src=%s, 回包来源=%s, 收到=%v", f.Detail, f.ObservedSrc, f.ReplyFrom, f.Received)
		}
		p("  判定: %s（置信度 %s）", rep.NAT.Label, rep.NAT.Confidence)
		if rep.NAT.Premise != "" {
			p("  前提: %s", rep.NAT.Premise)
		}
		p("")
	}

	p("四、对方视角总表（探针观测 %d 条）", len(rep.Observations))
	for i, o := range rep.Observations {
		p("  %d. %-4s %s:%d → :%d", i+1, o.Kind, o.SrcIP, o.SrcPort, o.DstPort)
		if o.MSS > 0 {
			p("      TCP: mss=%d wscale=%v sack=%v ts=%v ecn=%v rtt=%dus", o.MSS, o.WScale, o.SACK, o.TS, o.ECN, o.RTTUs)
		}
		if o.JA3 != "" {
			p("      TLS: ja3=%s ja4=%s sni=%s", o.JA3, o.JA4, o.SNI)
		}
		if o.HTTPMethod != "" {
			p("      HTTP: %s %s", o.HTTPMethod, o.HTTPPath)
			for _, h := range o.HTTPHeaders {
				p("        %s: %s", h.Key, h.Value)
			}
		}
		if o.ReplyFrom != "" {
			p("      UDP: reply_from=%s", o.ReplyFrom)
		}
	}
	p("")

	renderEndSections(p, rep)
	p("八、端口连通性 [观测点: 客户端尝试 + 探针回报比对]")
	for _, pc := range rep.Ports {
		status := "不通"
		if pc.Connected {
			status = "通"
		}
		confirm := "探针未观测"
		if pc.ProbeSaw {
			confirm = "探针确认"
		}
		mark := "一致"
		if !pc.Consistent {
			mark = "不一致"
		}
		p("  :%d/%s %s（%s）[%s]", pc.Port, pc.Proto, status, confirm, mark)
	}
	p("")
	if rep.MTU != nil {
		p("九、路径层 — 路径 MTU [观测点: %s]", rep.MTU.ObservedBy)
		bl := ""
		if rep.MTU.Blackhole {
			bl = " [疑似 PMTU 黑洞]"
		}
		p("  %d%s", rep.MTU.PathMTU, bl)
		if rep.MTU.Note != "" {
			p("  %s", rep.MTU.Note)
		}
		p("")
	}
	if rep.DNS != nil {
		p("十、路径层 — DNS [观测点: %s]", rep.DNS.ObservedBy)
		p("  %s 系统解析: %s", rep.DNS.Host, joinOrNA(rep.DNS.SystemAnswers))
		p("  %s DoH 解析: %s", rep.DNS.Host, joinOrNA(rep.DNS.DoHAnswers))
		p("  判定: %s", rep.DNS.Judgment)
		if rep.DNS.Premise != "" {
			p("  前提: %s", rep.DNS.Premise)
		}
		p("")
	}
	if rep.Reputation != nil {
		p("十一、出口层 — IP 信誉 [观测点: %s]", rep.Reputation.ObservedBy)
		if rep.Reputation.Source == "unavailable" {
			p("  不可用: %s", rep.Reputation.Note)
		} else {
			p("  %s %s %s %s", rep.Reputation.Country, rep.Reputation.Region, rep.Reputation.City, rep.Reputation.ISP)
			if rep.Reputation.AS != "" {
				p("  AS: %s", rep.Reputation.AS)
			}
			marks := []string{}
			if rep.Reputation.Proxy {
				marks = append(marks, "代理标记")
			}
			if rep.Reputation.Hosting {
				marks = append(marks, "机房标记")
			}
			if len(marks) > 0 {
				p("  标记: %s", strings.Join(marks, ", "))
			}
		}
		p("")
	}

	if rep.Direct != nil {
		renderDirectComparison(p, rep)
	}

	p("备注")
	for _, n := range rep.Notes {
		p("  [%s] %s", n.Level, n.Text)
	}
}

func renderAttribution(p func(string, ...any), l Local) {
	if l.TUN {
		p("  归因: TUN %s 接管 → 探针观测为代理出口（非本机直连）", l.TUNInterface)
	}
	if l.FakeIP {
		p("  归因: fake-ip 命中（%s）", l.FakeIPNote)
	}
	if l.ProxyStack != "" {
		p("  归因: 代理栈 %s", l.ProxyStack)
	}
	if l.UDP == "tun-blocked" {
		p("  归因: UDP 未被代理转发（非端口封锁）")
	}
	if l.Note != "" {
		p("  归因: %s", l.Note)
	}
}

func renderEndSections(p func(string, ...any), rep *Report) {
	if rep.TCP != nil {
		p("五、终点层 — TCP 指纹 [观测点: %s]", rep.TCP.ObservedBy)
		p("  mss=%d wscale=%v sack=%v ts=%v ecn=%v rtt=%.2fms", rep.TCP.MSS, rep.TCP.WScale, rep.TCP.SACK, rep.TCP.TS, rep.TCP.ECN, rep.TCP.RTTMs)
		p("")
	}
	if rep.TLS != nil {
		p("六、终点层 — TLS 指纹 [观测点: %s]", rep.TLS.ObservedBy)
		p("  ja3=%s", rep.TLS.JA3)
		p("  ja4=%s", rep.TLS.JA4)
		if rep.TLS.SNI != "" {
			p("  sni=%s", rep.TLS.SNI)
		}
		p("")
	}
	if rep.HTTP != nil {
		p("七、终点层 — HTTP 视角 [观测点: %s]", rep.HTTP.ObservedBy)
		p("  %s %s", rep.HTTP.Method, rep.HTTP.Path)
		for _, h := range rep.HTTP.Headers {
			p("    %s: %s", h.Key, h.Value)
		}
		if len(rep.HTTP.Traces) > 0 {
			p("  透明代理痕迹:")
			for _, t := range rep.HTTP.Traces {
				p("    - %s", t)
			}
		}
		p("")
	}
}

// renderDirectComparison draws the dual-column comparison (直连 vs 当前路径).
func renderDirectComparison(p func(string, ...any), rep *Report) {
	main := rep
	dir := rep.Direct
	p("十二、直连对比（直连路径 vs 主路径）")
	row := func(name string, a, b any) {
		p("  %-12s %-28v vs %v", name, a, b)
	}
	row("公网 IP", joinOrNA(dir.Overview.PublicIPs), joinOrNA(main.Overview.PublicIPs))
	row("NAT 类型", natLabel(dir), natLabel(main))
	row("TCP MSS", tcpMSS(dir), tcpMSS(main))
	row("TLS JA3", tlsJA3(dir), tlsJA3(main))
	row("路径 MTU", mtuOf(dir), mtuOf(main))
	row("DNS", dnsOf(dir), dnsOf(main))
	p("")
}

func natLabel(rep *Report) string {
	if rep.NAT == nil {
		return "n/a"
	}
	return rep.NAT.Label
}

func tcpMSS(rep *Report) any {
	if rep.TCP == nil || rep.TCP.MSS == 0 {
		return "n/a"
	}
	return rep.TCP.MSS
}

func tlsJA3(rep *Report) string {
	if rep.TLS == nil {
		return "n/a"
	}
	return rep.TLS.JA3
}

func mtuOf(rep *Report) any {
	if rep.MTU == nil {
		return "n/a"
	}
	return rep.MTU.PathMTU
}

func dnsOf(rep *Report) string {
	if rep.DNS == nil {
		return "n/a"
	}
	return rep.DNS.Judgment
}

// PathMTUStr returns the path MTU as the text renderer prints it.
func (m *MTUItem) PathMTUStr() string {
	if m == nil {
		return ""
	}
	return fmt.Sprintf("%d", m.PathMTU)
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func joinOrNA(vals []string) string {
	if len(vals) == 0 {
		return "n/a"
	}
	return strings.Join(vals, ", ")
}

func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}
