package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ReputationResult is the IP reputation lookup for the probe-observed
// public exit IP (ASN/ISP/hosting/proxy signals).
type ReputationResult struct {
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`
	Region  string `json:"region,omitempty"`
	City    string `json:"city,omitempty"`
	ISP     string `json:"isp,omitempty"`
	Org     string `json:"org,omitempty"`
	AS      string `json:"as,omitempty"`
	Proxy   bool   `json:"proxy"`
	Hosting bool   `json:"hosting"`
	Source  string `json:"source"` // ip-api | ipinfo | unavailable
	Note    string `json:"note,omitempty"`
}

// QueryReputation looks up ip first via ip-api (free tier, no key), then
// ipinfo when a token is supplied. Failures degrade to an "unavailable"
// result with a note — never a crash (ACC-P2-007).
func QueryReputation(ctx context.Context, ip, ipinfoToken, ipAPIBase string, timeout time.Duration) *ReputationResult {
	res, err := queryIPAPI(ctx, ip, ipAPIBase, timeout)
	if err == nil && res != nil {
		return res // success, or a definitive ip-api "fail" (e.g. reserved IP)
	}
	if ipinfoToken != "" {
		if r := queryIPInfo(ctx, ip, ipinfoToken, timeout); r != nil {
			return r
		}
	}
	note := "ip-api 查询失败"
	if err != nil {
		note += ": " + err.Error()
	}
	return &ReputationResult{IP: ip, Source: "unavailable", Note: note}
}

// ipAPIBase defaults to http://ip-api.com/json (free tier is HTTP-only);
// tests inject an unreachable base to keep hermetic.
func queryIPAPI(ctx context.Context, ip, base string, timeout time.Duration) (*ReputationResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u := fmt.Sprintf("%s/%s?fields=status,message,country,region,city,isp,org,as,proxy,hosting", base, ip)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var d struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Country string `json:"country"`
		Region  string `json:"region"`
		City    string `json:"city"`
		ISP     string `json:"isp"`
		Org     string `json:"org"`
		AS      string `json:"as"`
		Proxy   bool   `json:"proxy"`
		Hosting bool   `json:"hosting"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	if d.Status != "success" {
		msg := d.Message
		if msg == "" {
			msg = "ip-api 拒绝该地址（可能是私网/保留地址）"
		}
		return &ReputationResult{IP: ip, Source: "unavailable", Note: "ip-api: " + msg}, nil
	}
	return &ReputationResult{
		IP: ip, Country: d.Country, Region: d.Region, City: d.City,
		ISP: d.ISP, Org: d.Org, AS: d.AS, Proxy: d.Proxy, Hosting: d.Hosting,
		Source: "ip-api",
	}, nil
}

func queryIPInfo(ctx context.Context, ip, token string, timeout time.Duration) *ReputationResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u := fmt.Sprintf("https://ipinfo.io/%s/json", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var d struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
		Region  string `json:"region"`
		City    string `json:"city"`
		Org     string `json:"org"` // e.g. "AS13335 Cloudflare, Inc"
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return nil
	}
	return &ReputationResult{
		IP: d.IP, Country: d.Country, Region: d.Region, City: d.City, Org: d.Org,
		Source: "ipinfo",
	}
}
