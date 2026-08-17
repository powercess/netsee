package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DNSResult is the system-resolver vs DoH comparison with an honest
// judgment (the doc forbids crying wolf: CDN geo-DNS legitimately
// differs, so a mismatch alone is low-confidence).
type DNSResult struct {
	Host           string   `json:"host"`
	SystemAnswers  []string `json:"system_answers"`
	DoHAnswers     []string `json:"doh_answers"`
	DoHStatus      string   `json:"doh_status"` // ok | skipped | unavailable
	Same           bool     `json:"same"`
	FakeIPDetected bool     `json:"fake_ip_detected"`
	Judgment       string   `json:"judgment"`
	Premise        string   `json:"premise,omitempty"`
}

// RunDNS resolves host via the system resolver and the DoH endpoint, then
// compares. A system answer inside the fake-ip range is a definitive
// "DNS 被代理接管" signal and suppresses the hijack finding.
func RunDNS(ctx context.Context, host, dohURL string, timeout time.Duration) (*DNSResult, error) {
	res := &DNSResult{Host: host}
	r := &net.Resolver{}
	ips, err := r.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("system resolve: %w", err)
	}
	for _, ip := range ips {
		res.SystemAnswers = append(res.SystemAnswers, ip.String())
	}
	res.FakeIPDetected = detectFakeIPAnswer(res.SystemAnswers)

	if dohURL == "" {
		res.DoHStatus = "skipped"
	} else {
		answers, err := queryDoH(ctx, dohURL, host, timeout)
		if err != nil {
			res.DoHStatus = "unavailable"
			res.Premise = "DoH 查询失败: " + err.Error()
		} else {
			res.DoHAnswers = answers
			res.DoHStatus = "ok"
		}
	}

	res.Same = setsEqual(res.SystemAnswers, res.DoHAnswers)
	judgeDNS(res)
	return res, nil
}

// judgeDNS derives the honest judgment from the raw answers (testable
// without network). fake-ip suppresses the hijack finding; a DoH-unusable
// state is reported as such; a plain mismatch is only low-confidence
// because CDN geo-DNS legitimately differs.
func judgeDNS(res *DNSResult) {
	switch {
	case res.FakeIPDetected:
		res.Judgment = "DNS 被代理接管（fake-ip）"
	case res.DoHStatus != "ok":
		res.Judgment = "仅系统解析（DoH 不可用，无法对比）"
	case res.Same:
		res.Judgment = "一致（未检测到劫持）"
	default:
		res.Judgment = "疑似分流/劫持（低置信度）"
		res.Premise = "CDN 地域解析也会导致系统与 DoH 结果差异；已列出双方原始答案"
	}
}

// queryDoH queries a DoH RFC8484-style GET endpoint (Google/Cloudflare
// JSON API) for both A and AAAA records.
func queryDoH(ctx context.Context, dohURL, host string, timeout time.Duration) ([]string, error) {
	var out []string
	for _, typ := range []string{"A", "AAAA"} {
		ctx2, cancel := context.WithTimeout(ctx, timeout)
		u := fmt.Sprintf("%s?name=%s&type=%s", dohURL, host, typ)
		req, err := http.NewRequestWithContext(ctx2, "GET", u, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("DoH %s status %d", typ, resp.StatusCode)
		}
		var d struct {
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if err := json.Unmarshal(body, &d); err != nil {
			return nil, err
		}
		for _, a := range d.Answer {
			if a.Data != "" {
				out = append(out, a.Data)
			}
		}
	}
	return out, nil
}

func setsEqual(a, b []string) bool {
	sa, sb := sortedCopy(a), sortedCopy(b)
	return strings.Join(sa, ",") == strings.Join(sb, ",")
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
