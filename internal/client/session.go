package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"netsee/internal/proto"
)

// Session is the probe-side measurement session: it owns the session UUID,
// port self-discovery and observation pull-back.
type Session struct {
	id     string
	probe  string // base HTTP URL of the probe, e.g. http://1.2.3.4:8080
	info   *Info
	client *http.Client
}

// NewSession discovers the probe and allocates a session ID.
func NewSession(ctx context.Context, probeURL string, timeout time.Duration) (*Session, error) {
	hc := &http.Client{Timeout: timeout}
	resp, err := hc.Get(probeURL + "/api/info")
	if err != nil {
		return nil, fmt.Errorf("probe /api/info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("probe /api/info: status %d", resp.StatusCode)
	}
	var info Info
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode /api/info: %w", err)
	}
	return &Session{id: proto.NewID(), probe: probeURL, info: &info, client: hc}, nil
}

// ID returns the session UUID.
func (s *Session) ID() string { return s.id }

// Info returns the port self-discovery response.
func (s *Session) Info() *Info { return s.info }

// Base returns the probe base URL.
func (s *Session) Base() string { return s.probe }

// Pull returns all observations recorded for the session. It retries
// briefly because the probe records asynchronously.
func (s *Session) Pull(ctx context.Context) ([]proto.Obs, error) {
	url := fmt.Sprintf("%s/api/session/%s", s.probe, s.id)
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := s.client.Get(url)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var obs []proto.Obs
			if err := json.Unmarshal(body, &obs); err != nil {
				return nil, err
			}
			return obs, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("session %s not found", s.id)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// HTTPEcho sends an HTTP request to the probe so it records the full
// request headers as seen by the network.
func (s *Session) HTTPEcho(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/echo", s.probe), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Netsee-Session", s.id)
	req.Header.Set("User-Agent", "netsee-client/0.1")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("echo status %d", resp.StatusCode)
	}
	return nil
}

// TLSSniff connects to the TLS port with an SNI of "<session>.n". The
// probe sniffs the ClientHello (Go crypto/tls generates a real one) and
// records JA3/JA4. Only a TCP-dial failure is an error; the handshake is
// expected to fail because the probe never completes it.
func (s *Session) TLSSniff(ctx context.Context) error {
	addr := net.JoinHostPort(hostOf(s.probe), strconv.Itoa(s.info.TLSPort))
	d := net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: s.id + ".1"})
	_ = conn.Handshake()
	return nil
}

// TCPReach attempts a plain TCP connect to an extra port (reach test).
func (s *Session) TCPReach(ctx context.Context, port int) error {
	addr := net.JoinHostPort(hostOf(s.probe), strconv.Itoa(port))
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	payload := fmt.Sprintf(`{"session":"%s","kind":"reach"}`, s.id)
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		return err
	}
	return nil
}

// hostOf extracts the host part of a base URL.
func hostOf(base string) string {
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		return base
	}
	return u.Hostname()
}
