package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"netsee/internal/proto"
)

// startTestServer boots a probe on 127.0.0.1 with ephemeral ports and
// registers cleanup.
func startTestServer(t *testing.T, cfg Config) (*Server, *proto.Info) {
	t.Helper()
	cfg.Bind = "127.0.0.1"
	srv := New(cfg)
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return srv, srv.Ports()
}

func baseConfig() Config {
	return Config{
		HTTPPort:    0,
		TLSPort:     0,
		UDPPort:     0,
		NATPort:     0,
		MaxUDP:      2048,
		ReadTimeout: 5 * time.Second,
	}
}

// fetchSession GETs /api/session/{id} with a short retry loop: the probe
// records observations asynchronously, so the client must tolerate a
// small window.
func fetchSession(t *testing.T, info *proto.Info, id string) []*proto.Obs {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/api/session/%s", info.HTTPPort, id)
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var obs []*proto.Obs
			if err := json.Unmarshal(body, &obs); err != nil {
				t.Fatalf("decode obs: %v", err)
			}
			return obs
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s: status %d", url, resp.StatusCode)
		}
		if time.Now().After(deadline) {
			t.Fatalf("session %s not found within deadline", id)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func fetchInfo(t *testing.T, port int) *proto.Info {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/info", port))
	if err != nil {
		t.Fatalf("GET /api/info: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/info: status %d", resp.StatusCode)
	}
	var info proto.Info
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatalf("decode info: %v", err)
	}
	return &info
}

func httpGetStatus(t *testing.T, url string, status int) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp.Body.Close()
	if resp.StatusCode != status {
		t.Fatalf("GET %s: status %d, want %d", url, resp.StatusCode, status)
	}
	return resp
}

// --- ACC-P1-001: HTTP echo session pull-back ------------------------------

func TestHTTPEchoSessionPullback(t *testing.T) {
	srv, info := startTestServer(t, baseConfig())
	session := proto.NewID()

	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/measure", info.HTTPPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Netsee-Session", session)
	req.Header.Set("X-Custom-Header", "netsee-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("echo request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("echo status %d", resp.StatusCode)
	}

	obs := fetchSession(t, info, session)
	var found *proto.Obs
	for _, o := range obs {
		if o.Kind == proto.ObsHTTP && o.HTTP != nil && o.HTTP.Path == "/measure" {
			found = o
			break
		}
	}
	if found == nil {
		t.Fatalf("no http obs for /measure in %d obs", len(obs))
	}
	if found.Session != session {
		t.Errorf("Session = %q, want %q", found.Session, session)
	}
	if found.SrcIP != "127.0.0.1" || found.SrcPort == 0 {
		t.Errorf("SrcIP/SrcPort = %s/%d, want 127.0.0.1/<ephemeral>", found.SrcIP, found.SrcPort)
	}
	if found.DstPort != info.HTTPPort {
		t.Errorf("DstPort = %d, want %d", found.DstPort, info.HTTPPort)
	}
	if found.HTTP.Method != "GET" || found.HTTP.Proto != "HTTP/1.1" {
		t.Errorf("HTTP = %+v", found.HTTP)
	}
	custom := false
	host := false
	for _, h := range found.HTTP.Headers {
		switch h.Key {
		case "X-Custom-Header":
			custom = h.Value == "netsee-test"
		case "Host":
			host = true
		}
	}
	if !custom || !host {
		t.Errorf("headers missing custom/host: %+v", found.HTTP.Headers)
	}
	if runtime.GOOS == "linux" {
		if found.TCPInfo == nil {
			t.Error("TCPInfo missing on linux")
		} else if found.TCPInfo.MSS == 0 {
			t.Errorf("TCPInfo.MSS = 0, want > 0: %+v", found.TCPInfo)
		}
	}
	// Request without a session header must not create a session.
	httpGetStatus(t, fmt.Sprintf("http://127.0.0.1:%d/", info.HTTPPort), http.StatusOK)
	if srv.SessionCount() != 1 {
		t.Errorf("SessionCount = %d, want 1 (no-session requests must not create sessions)", srv.SessionCount())
	}
}

// --- ACC-P1-005: /api/info port self-discovery ----------------------------

func TestInfoSelfDiscovery(t *testing.T) {
	srv, info := startTestServer(t, baseConfig())
	got := fetchInfo(t, info.HTTPPort)
	if got.HTTPPort != info.HTTPPort || got.TLSPort != info.TLSPort ||
		got.UDPPort != info.UDPPort || got.NATPort != info.NATPort {
		t.Errorf("info mismatch: got %+v, want ports %+v", got, info)
	}
	if got.ProtocolVersion != "1" {
		t.Errorf("ProtocolVersion = %q", got.ProtocolVersion)
	}
	if got.SecondIP {
		t.Error("SecondIP should be false without -second-ip")
	}
	_ = srv
}

// --- ACC-P1-007: sessions are not enumerable ------------------------------

func TestSessionNotFound(t *testing.T) {
	_, info := startTestServer(t, baseConfig())
	httpGetStatus(t, fmt.Sprintf("http://127.0.0.1:%d/api/session/%s", info.HTTPPort, proto.NewID()), http.StatusNotFound)
	httpGetStatus(t, fmt.Sprintf("http://127.0.0.1:%d/api/session/not-a-uuid", info.HTTPPort), http.StatusNotFound)
}

// --- ACC-P1-006: TTL cleanup ----------------------------------------------

func TestSessionTTLExpiry(t *testing.T) {
	cfg := baseConfig()
	cfg.TTL = 150 * time.Millisecond
	srv, info := startTestServer(t, cfg)
	session := proto.NewID()

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", info.HTTPPort), nil)
	req.Header.Set("X-Netsee-Session", session)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if srv.SessionCount() != 1 {
		t.Fatalf("SessionCount = %d after insert, want 1", srv.SessionCount())
	}
	time.Sleep(400 * time.Millisecond)
	httpGetStatus(t, fmt.Sprintf("http://127.0.0.1:%d/api/session/%s", info.HTTPPort, session), http.StatusNotFound)
	srv.GC()
	if n := srv.SessionCount(); n != 0 {
		t.Errorf("SessionCount = %d after TTL+GC, want 0", n)
	}
}

// --- ACC-P1-003: UDP echo same-port and NAT other-port replies ------------

// udpRoundTrip exchanges one datagram with an unconnected socket: the
// kernel must not filter replies by source address, because the NAT test
// expects a reply from a different source port (real NAT semantics).
func udpRoundTrip(t *testing.T, dst *net.UDPAddr, payload []byte) ([]byte, *net.UDPAddr) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.WriteToUDP(payload, dst); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return buf[:n], addr
}

func TestUDPEchoSamePort(t *testing.T) {
	_, info := startTestServer(t, baseConfig())
	session := proto.NewID()
	payload := fmt.Sprintf(`{"session":"%s","kind":"echo"}`, session)

	reply, from := udpRoundTrip(t, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: info.UDPPort}, []byte(payload))
	if string(reply) != payload {
		t.Errorf("reply = %q, want echo of %q", reply, payload)
	}
	if from.Port != info.UDPPort {
		t.Errorf("reply source port = %d, want udp port %d", from.Port, info.UDPPort)
	}
	obs := fetchSession(t, info, session)
	if len(obs) != 1 || obs[0].UDP == nil {
		t.Fatalf("expected one udp obs, got %+v", obs)
	}
	if obs[0].UDP.Kind != "echo" || obs[0].UDP.ReplyFrom != "same" || obs[0].UDP.PayloadLen != len(payload) {
		t.Errorf("udp obs = %+v", obs[0].UDP)
	}
}

func TestUDPNatOtherPort(t *testing.T) {
	_, info := startTestServer(t, baseConfig())
	session := proto.NewID()
	payload := fmt.Sprintf(`{"session":"%s","kind":"nat"}`, session)

	_, from := udpRoundTrip(t, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: info.UDPPort}, []byte(payload))
	if from.Port != info.NATPort {
		t.Errorf("nat reply source port = %d, want nat port %d", from.Port, info.NATPort)
	}
	obs := fetchSession(t, info, session)
	if len(obs) != 1 || obs[0].UDP == nil || obs[0].UDP.ReplyFrom != "other-port" {
		t.Fatalf("expected nat obs with reply_from other-port, got %+v", obs)
	}
}

func TestUDPUnknownKindDropped(t *testing.T) {
	_, info := startTestServer(t, baseConfig())
	session := proto.NewID()
	payload := fmt.Sprintf(`{"session":"%s","kind":"bogus"}`, session)

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: info.UDPPort})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, _, err := conn.ReadFromUDP(buf); err == nil {
		t.Error("expected no reply for unknown kind")
	}
	// The session must never be created: pull-back is 404.
	httpGetStatus(t, fmt.Sprintf("http://127.0.0.1:%d/api/session/%s", info.HTTPPort, session), http.StatusNotFound)
}

// --- ACC-P1-004: TLS sniff with session from SNI --------------------------

func TestTLSSniffSession(t *testing.T) {
	_, info := startTestServer(t, baseConfig())
	session := proto.NewID()

	hb := &helloBuilder{
		recordVersion: 0x0301,
		legacyVersion: 0x0303,
		compressions:  []byte{0x00},
		ciphers:       []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030},
		extensions: []extEntry{
			sniExt(session + ".1"),
			alpnExt("h2"),
			suppVersionsExt(0x0304),
			groupsExt(0x0017, 0x0018, 0x0019),
			pointFormatsExt(0x00),
		},
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", info.TLSPort))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(hb.build()); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	obs := fetchSession(t, info, session)
	var found *proto.Obs
	for _, o := range obs {
		if o.Kind == proto.ObsTLS && o.TLS != nil && o.TLS.SNI == session+".1" {
			found = o
			break
		}
	}
	if found == nil {
		t.Fatalf("no tls obs for SNI %s.1 in %d obs", session, len(obs))
	}
	if found.Session != session {
		t.Errorf("Session = %q, want %q", found.Session, session)
	}
	if found.TLS.JA3 == "" || found.TLS.JA4 == "" {
		t.Errorf("empty fingerprints: %+v", found.TLS)
	}
	if len(found.TLS.JA3) != 32 || len(found.TLS.JA4) < 30 {
		t.Errorf("fingerprint shapes: JA3=%q JA4=%q", found.TLS.JA3, found.TLS.JA4)
	}
	if runtime.GOOS == "linux" && found.TCPInfo == nil {
		t.Error("TCPInfo missing on linux for TLS connection")
	}
}

// --- Extra ports (reach) ---------------------------------------------------

func TestExtraPortReach(t *testing.T) {
	cfg := baseConfig()
	cfg.ExtraPorts = []int{0}
	srv, info := startTestServer(t, cfg)
	extraPort := info.ExtraPorts[0]

	session := proto.NewID()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", extraPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	payload := fmt.Sprintf(`{"session":"%s","kind":"reach"}`, session)
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if !strings.Contains(string(buf[:n]), `"ok":true`) {
		t.Errorf("ack = %q", buf[:n])
	}

	obs := fetchSession(t, info, session)
	if len(obs) != 1 || obs[0].Kind != proto.ObsTCP || obs[0].DstPort != extraPort {
		t.Fatalf("expected tcp reach obs on port %d, got %+v", extraPort, obs)
	}
	if srv.SessionCount() != 1 {
		t.Errorf("SessionCount = %d, want 1", srv.SessionCount())
	}
}
