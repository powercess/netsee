package client

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"

	"netsee/internal/proto"
)

// Config configures one measurement run.
type Config struct {
	ProbeURL    string
	Timeout     time.Duration
	DoHURL      string
	DNSHost     string
	IPInfoToken string
	IPAPIBase   string // default http://ip-api.com/json; injectable for tests
	Direct      bool
}

func (c Config) normalize() Config {
	if c.ProbeURL == "" {
		c.ProbeURL = "http://127.0.0.1:8080"
	}
	if c.Timeout == 0 {
		c.Timeout = 15 * time.Second
	}
	if c.DNSHost == "" {
		c.DNSHost = "example.com"
	}
	if c.IPAPIBase == "" {
		c.IPAPIBase = "http://ip-api.com/json"
	}
	return c
}

// Run performs one full measurement. Failures are section-local (recorded
// as notes); only probe discovery failure aborts the run.
func (c Config) Run(ctx context.Context) (*Result, error) {
	c = c.normalize()
	started := time.Now()
	sess, err := NewSession(ctx, c.ProbeURL, c.Timeout)
	if err != nil {
		return nil, err
	}
	res := &Result{Session: sess.ID(), Started: started}
	defer func() { res.Duration = time.Since(started) }()
	res.addNote("info", "沿途节点有能力看到以下信息；是否真的在看取决于具体服务商。本工具测的是暴露面，不是实际被监视。")

	if local, lerr := CollectLocal(); lerr != nil {
		res.addNote("warn", "本地采集失败: "+lerr.Error())
	} else {
		res.Local = *local
		res.Attribution.TUN, res.Attribution.TUNInterface = detectTUN(local)
		if detectFakeIPResolvers(local.ResolvConf) {
			res.Attribution.FakeIP = true
			res.Attribution.FakeIPNote = "系统解析器指向 fake-ip 段（198.18.0.0/15），DNS 被代理接管"
		}
	}

	httpErr := sess.HTTPEcho(ctx)
	if httpErr != nil {
		res.addNote("warn", "HTTP echo: "+httpErr.Error())
	}
	tlsErr := sess.TLSSniff(ctx)
	if tlsErr != nil {
		res.addNote("warn", "TLS 嗅探: "+tlsErr.Error())
	}
	if nat, err := sess.RunNAT(ctx, c.Timeout); err != nil {
		res.addNote("warn", "NAT 测试: "+err.Error())
	} else {
		res.NAT = nat
	}
	if pmtu, err := sess.RunPMTU(ctx, c.Timeout); err != nil {
		res.addNote("warn", "PMTU: "+err.Error())
	} else {
		res.PMTU = pmtu
	}
	if dns, err := RunDNS(ctx, c.DNSHost, c.DoHURL, c.Timeout); err != nil {
		res.addNote("warn", "DNS: "+err.Error())
	} else {
		res.DNS = dns
	}

	obs, perr := sess.Pull(ctx)
	if perr != nil {
		res.addNote("warn", "拉取观测: "+perr.Error())
	}

	// Client-side connectivity outcomes per probe port.
	info := sess.Info()
	outcomes := map[int]bool{
		info.HTTPPort: httpErr == nil,
		info.TLSPort:  tlsErr == nil,
		info.UDPPort:  res.NAT != nil && res.NAT.EchoReceived,
		info.NATPort:  res.NAT != nil && res.NAT.NATReplyReceived,
	}
	for _, p := range info.ExtraPorts {
		outcomes[p] = sess.TCPReach(ctx, p) == nil
	}
	res.Probe = buildProbeResult(sess, obs, outcomes)
	res.PublicIPs = res.Probe.ExitIPs

	finalizeAttribution(&res.Attribution, res)

	if ip := primaryExitIP(res); ip != "" {
		res.Reputation = QueryReputation(ctx, ip, c.IPInfoToken, c.IPAPIBase, c.Timeout)
	}

	if c.Direct {
		if d, err := c.runDirect(ctx); err != nil {
			res.addNote("warn", "直连对比不可用: "+err.Error())
		} else {
			res.Direct = d
		}
	}
	return res, nil
}

// proxyTraceHeaders are the HTTP headers most commonly injected by
// transparent proxies / reverse proxies on the path.
var proxyTraceHeaders = []string{
	"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host",
	"Via", "Forwarded", "Proxy-Connection", "X-Real-Ip", "True-Client-Ip",
}

// transparentProxyTraces returns the injected-header traces found in the
// headers the probe received (path middlebox evidence).
func transparentProxyTraces(headers []proto.Header) []string {
	var traces []string
	for _, h := range headers {
		for _, t := range proxyTraceHeaders {
			if strings.EqualFold(h.Key, t) {
				traces = append(traces, h.Key+": "+h.Value)
			}
		}
	}
	return traces
}

// buildProbeResult converts probe observations into the structured view.
func buildProbeResult(sess *Session, obs []proto.Obs, outcomes map[int]bool) ProbeResult {
	pr := ProbeResult{
		ProbeURL:    sess.Base(),
		ProtocolVer: sess.Info().ProtocolVersion,
		Info:        sess.Info(),
	}
	exitIPs := map[string]bool{}
	sawPort := map[int]bool{}
	for _, o := range obs {
		if o.SrcIP == "" {
			continue
		}
		ob := Observation{Kind: string(o.Kind), SrcIP: o.SrcIP, SrcPort: o.SrcPort, DstPort: o.DstPort}
		if o.TCPInfo != nil {
			ob.MSS = o.TCPInfo.MSS
			ob.WScale = o.TCPInfo.WScale
			ob.SACK = o.TCPInfo.SACK
			ob.TS = o.TCPInfo.TS
			ob.ECN = o.TCPInfo.ECN
			ob.RTTUs = o.TCPInfo.RTTUs
		}
		if o.TLS != nil {
			ob.JA3, ob.JA4, ob.SNI = o.TLS.JA3, o.TLS.JA4, o.TLS.SNI
		}
		if o.UDP != nil {
			ob.ReplyFrom = o.UDP.ReplyFrom
		}
		if o.HTTP != nil {
			ob.HTTPMethod = o.HTTP.Method
			ob.HTTPPath = o.HTTP.Path
			ob.HTTPHeaders = o.HTTP.Headers
			ob.HTTPTraces = transparentProxyTraces(o.HTTP.Headers)
		}
		pr.Observations = append(pr.Observations, ob)
		exitIPs[o.SrcIP] = true
		sawPort[o.DstPort] = true
	}
	for ip := range exitIPs {
		pr.ExitIPs = append(pr.ExitIPs, ip)
	}
	sort.Strings(pr.ExitIPs)

	info := sess.Info()
	for _, port := range []int{info.HTTPPort, info.TLSPort, info.UDPPort, info.NATPort} {
		connected, ok := outcomes[port]
		if !ok {
			continue
		}
		prot := "tcp"
		if port == info.UDPPort || port == info.NATPort {
			prot = "udp"
		}
		pr.Connectivity = append(pr.Connectivity, PortCheck{
			Port: port, Proto: prot, Connected: connected,
			ProbeSaw: sawPort[port], Consistent: connected == sawPort[port],
		})
	}
	for _, p := range info.ExtraPorts {
		pr.Connectivity = append(pr.Connectivity, PortCheck{
			Port: p, Proto: "tcp", Connected: outcomes[p],
			ProbeSaw: sawPort[p], Consistent: outcomes[p] == sawPort[p],
		})
	}
	return pr
}

// finalizeAttribution completes the path attribution from measurement
// results (fake-ip answers, proxy stack, UDP forwarding).
func finalizeAttribution(a *Attribution, res *Result) {
	if res.DNS != nil && res.DNS.FakeIPDetected {
		a.FakeIP = true
		a.FakeIPNote = "系统解析返回 fake-ip 段（198.18.0.0/15），DNS 被代理接管"
	}
	if a.TUN {
		a.ProxyStack = inferProxyStack(res.Probe.Observations)
		if a.ProxyStack == nil {
			a.Note = "流量经 TUN 接管，探针观测为代理出口（程序未知，不点名）"
		}
		tcpOK := false
		for _, pc := range res.Probe.Connectivity {
			if pc.Proto == "tcp" && pc.Connected {
				tcpOK = true
				break
			}
		}
		if res.NAT != nil && !res.NAT.EchoReceived && tcpOK {
			a.UDP = "tun-blocked"
			if a.Note != "" {
				a.Note += "；TCP 通但 UDP 不通，归因于 TUN 代理不转发 UDP"
			} else {
				a.Note = "TCP 通但 UDP 不通，归因于 TUN 代理不转发 UDP（非端口封锁）"
			}
		}
	}
}

func primaryExitIP(res *Result) string {
	if len(res.Probe.ExitIPs) == 0 {
		return ""
	}
	return res.Probe.ExitIPs[0]
}

// runDirect adds a host route to the probe via the physical gateway
// (bypassing TUN), re-measures, and removes the route. Best-effort:
// requires root and a physical default route; failures are explicit.
func (c Config) runDirect(ctx context.Context) (*Result, error) {
	probeHost := hostOf(c.ProbeURL)
	ip := net.ParseIP(probeHost)
	if ip == nil {
		return nil, fmt.Errorf("探针地址 %q 非 IP，无法加直连路由", probeHost)
	}
	if ip.IsLoopback() {
		return nil, fmt.Errorf("探针为回环地址，无需直连路由")
	}
	iface, gw, err := PhysicalDefaultV4()
	if err != nil {
		return nil, fmt.Errorf("无物理直连路由: %w", err)
	}
	if isTUNInterface(iface) {
		return nil, fmt.Errorf("默认路由仍为 TUN，无法建立直连路径")
	}
	if out, err := exec.CommandContext(ctx, "ip", "route", "add", probeHost+"/32", "via", gw, "dev", iface).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("直连路由添加失败（需 root 或代理覆盖路由守卫）: %v: %s", err, strings.TrimSpace(string(out)))
	}
	defer exec.Command("ip", "route", "del", probeHost+"/32", "via", gw, "dev", iface).Run()

	sub := c
	sub.Direct = false
	return sub.Run(ctx)
}
