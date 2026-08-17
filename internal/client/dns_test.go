package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJudgeDNS(t *testing.T) {
	cases := []struct {
		name string
		res  *DNSResult
		want string
	}{
		{
			name: "fake-ip suppresses hijack",
			res:  &DNSResult{SystemAnswers: []string{"198.18.0.5"}, DoHAnswers: []string{"93.184.216.34"}, DoHStatus: "ok", FakeIPDetected: true},
			want: "DNS 被代理接管（fake-ip）",
		},
		{
			name: "consistent",
			res:  &DNSResult{SystemAnswers: []string{"93.184.216.34"}, DoHAnswers: []string{"93.184.216.34"}, DoHStatus: "ok", Same: true},
			want: "一致（未检测到劫持）",
		},
		{
			name: "DoH unavailable",
			res:  &DNSResult{SystemAnswers: []string{"93.184.216.34"}, DoHStatus: "unavailable"},
			want: "仅系统解析（DoH 不可用，无法对比）",
		},
		{
			name: "mismatch low confidence",
			res:  &DNSResult{SystemAnswers: []string{"1.2.3.4"}, DoHAnswers: []string{"5.6.7.8"}, DoHStatus: "ok"},
			want: "疑似分流/劫持（低置信度）",
		},
	}
	for _, tc := range cases {
		judgeDNS(tc.res)
		if tc.res.Judgment != tc.want {
			t.Errorf("%s: judgment = %q, want %q", tc.name, tc.res.Judgment, tc.want)
		}
	}
}

func TestSetsEqual(t *testing.T) {
	if !setsEqual([]string{"1.2.3.4", "5.6.7.8"}, []string{"5.6.7.8", "1.2.3.4"}) {
		t.Error("unordered sets should be equal")
	}
	if setsEqual([]string{"1.2.3.4"}, []string{"1.2.3.5"}) {
		t.Error("different sets should differ")
	}
}

// TestQueryDoH exercises the DoH JSON parsing against a local fixture
// server (no external network).
func TestQueryDoH(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("type") == "A" {
			io.WriteString(w, `{"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"93.184.216.34"}]}`)
			return
		}
		io.WriteString(w, `{"Answer":[{"name":"example.com.","type":28,"TTL":300,"data":"2606:2800:220:1:248:1893:25c8:1946"}]}`)
	}))
	defer srv.Close()

	got, err := queryDoH(t.Context(), srv.URL+"/resolve", "example.com", 2e9)
	if err != nil {
		t.Fatalf("queryDoH: %v", err)
	}
	want := []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// order: A then AAAA
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	_ = json.Valid
}
