package probe

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestProbeSurvivesMalformedLoad floods every probe port with malformed
// and oversized traffic (ACC-P5-001): the probe must not crash, must keep
// serving the control API, and must not create sessions from garbage.
func TestProbeSurvivesMalformedLoad(t *testing.T) {
	srv, info := startTestServer(t, baseConfig())
	httpAddr := fmt.Sprintf("127.0.0.1:%d", info.HTTPPort)
	tlsAddr := fmt.Sprintf("127.0.0.1:%d", info.TLSPort)
	udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: info.UDPPort}

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(3)
		go func() { // malformed HTTP
			defer wg.Done()
			if c, err := net.Dial("tcp", httpAddr); err == nil {
				_, _ = c.Write([]byte("GARBAGE\r\n\r\n"))
				_, _ = c.Write(make([]byte, 70000)) // > MaxHeaderBytes
				c.Close()
			}
		}()
		go func() { // garbage on TLS port
			defer wg.Done()
			if c, err := net.Dial("tcp", tlsAddr); err == nil {
				_, _ = c.Write([]byte("0000 this is not a ClientHello 1111"))
				_, _ = c.Write(make([]byte, 80000)) // > maxHelloBytes
				c.Close()
			}
		}()
		go func() { // malformed + oversized UDP
			defer wg.Done()
			if c, err := net.DialUDP("udp", nil, udpAddr); err == nil {
				_, _ = c.Write([]byte{0xff, 0xfe, 0xfd, 0x00, 0x01})
				_, _ = c.Write(make([]byte, 5000)) // > MaxUDP 2048
				c.Close()
			}
		}()
	}
	wg.Wait()

	// The probe must still answer the control API.
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/info", info.HTTPPort))
	if err != nil {
		t.Fatalf("probe unresponsive after flood: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("api/info status %d after flood", resp.StatusCode)
	}

	// Garbage must not create sessions.
	if n := srv.SessionCount(); n != 0 {
		t.Errorf("SessionCount = %d after garbage flood, want 0", n)
	}
}

// TestProbeStaysResponsiveDuringLoad runs a valid measurement while the
// probe is under concurrent malformed load: valid traffic still works.
func TestProbeStaysResponsiveDuringLoad(t *testing.T) {
	srv, info := startTestServer(t, baseConfig())

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // background malformed flood
		defer wg.Done()
		udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: info.UDPPort}
		for {
			select {
			case <-stop:
				return
			default:
			}
			if c, err := net.DialUDP("udp", nil, udpAddr); err == nil {
				_, _ = c.Write([]byte("junk"))
				c.Close()
			}
		}
	}()

	// A valid echo session must still record under load.
	session := "01234567-89ab-cdef-0123-456789abcdef"
	udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: info.UDPPort}
	c, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(fmt.Sprintf(`{"session":"%s","kind":"echo"}`, session))
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	if _, _, err := c.ReadFromUDP(buf); err != nil {
		t.Fatalf("echo reply lost under load: %v", err)
	}
	c.Close()
	close(stop)
	wg.Wait()

	obs := fetchSession(t, info, session)
	if len(obs) == 0 || obs[0].Kind != "udp" {
		t.Errorf("valid session lost under load: %+v", obs)
	}
	_ = srv
}
