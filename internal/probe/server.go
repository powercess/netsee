// Package probe implements the netsee-probe server: the remote observation
// point that records "what the network sees" about a client's connections.
package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netsee/internal/proto"
)

// Config configures the probe listeners and limits.
type Config struct {
	Bind        string
	HTTPPort    int
	TLSPort     int
	UDPPort     int
	NATPort     int
	ExtraPorts  []int
	SecondIP    string
	TTL         time.Duration
	MaxSessions int
	MaxUDP      int
	ReadTimeout time.Duration
}

func applyDefaults(cfg Config) Config {
	if cfg.Bind == "" {
		cfg.Bind = "0.0.0.0"
	}
	// Ports are left as-is: 0 means an ephemeral port (used by tests and
	// useful for the CLI); the CLI passes explicit defaults.
	if cfg.TTL == 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.MaxSessions == 0 {
		cfg.MaxSessions = 10000
	}
	if cfg.MaxUDP == 0 {
		cfg.MaxUDP = 2048
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 10 * time.Second
	}
	return cfg
}

// Server is the probe: it binds the declared ports and records
// observations into an in-memory session registry.
type Server struct {
	cfg     Config
	store   *proto.Store
	httpSrv *http.Server

	httpLn  net.Listener
	tlsLn   net.Listener
	udpLn   *net.UDPConn
	natLn   *net.UDPConn
	extraLn []net.Listener

	infoCache *proto.Info

	done chan struct{}
	wg   sync.WaitGroup
}

// New creates a probe server from cfg.
func New(cfg Config) *Server {
	cfg = applyDefaults(cfg)
	return &Server{
		cfg:   cfg,
		store: proto.NewStore(cfg.TTL, cfg.MaxSessions),
		done:  make(chan struct{}),
	}
}

// Start binds all listeners and launches the serve loops. Any bind
// failure aborts the startup and closes already-bound sockets.
func (s *Server) Start() error {
	httpLn, err := net.Listen("tcp", net.JoinHostPort(s.cfg.Bind, strconv.Itoa(s.cfg.HTTPPort)))
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}
	s.httpLn = httpLn

	closeAll := func() {
		httpLn.Close()
		if s.tlsLn != nil {
			s.tlsLn.Close()
		}
		if s.udpLn != nil {
			s.udpLn.Close()
		}
		if s.natLn != nil {
			s.natLn.Close()
		}
		for _, ln := range s.extraLn {
			ln.Close()
		}
	}

	tlsLn, err := net.Listen("tcp", net.JoinHostPort(s.cfg.Bind, strconv.Itoa(s.cfg.TLSPort)))
	if err != nil {
		closeAll()
		return fmt.Errorf("tls listen: %w", err)
	}
	s.tlsLn = tlsLn

	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: parseIP(s.cfg.Bind), Port: s.cfg.UDPPort})
	if err != nil {
		closeAll()
		return fmt.Errorf("udp listen: %w", err)
	}
	s.udpLn = udpLn

	natAddr := &net.UDPAddr{IP: parseIP(s.cfg.Bind), Port: s.cfg.NATPort}
	if s.cfg.SecondIP != "" {
		natAddr.IP = net.ParseIP(s.cfg.SecondIP)
	}
	natLn, err := net.ListenUDP("udp", natAddr)
	if err != nil {
		closeAll()
		return fmt.Errorf("nat listen: %w", err)
	}
	s.natLn = natLn

	for _, p := range s.cfg.ExtraPorts {
		ln, err := net.Listen("tcp", net.JoinHostPort(s.cfg.Bind, strconv.Itoa(p)))
		if err != nil {
			closeAll()
			return fmt.Errorf("extra port %d: %w", p, err)
		}
		s.extraLn = append(s.extraLn, ln)
	}

	s.infoCache = s.buildInfo()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/info", s.handleInfo)
	mux.HandleFunc("GET /api/session/{id}", s.handleSession)
	mux.HandleFunc("/", s.handleEcho)
	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: s.cfg.ReadTimeout,
		ReadTimeout:       s.cfg.ReadTimeout,
		WriteTimeout:      s.cfg.ReadTimeout,
		IdleTimeout:       s.cfg.ReadTimeout,
		MaxHeaderBytes:    64 * 1024,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
	}

	s.wg.Add(4 + len(s.extraLn))
	go s.serveHTTP()
	go s.serveTLS()
	go s.serveUDP()
	for _, ln := range s.extraLn {
		go s.acceptExtra(ln)
	}
	go s.gcLoop()
	return nil
}

// serveHTTP runs the HTTP server (control API + echo observations).
func (s *Server) serveHTTP() {
	defer s.wg.Done()
	err := s.httpSrv.Serve(s.httpLn)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("http serve: %v", err)
	}
}

// serveTLS accepts connections and hands them to the ClientHello sniffer.
func (s *Server) serveTLS() {
	defer s.wg.Done()
	for {
		conn, err := s.tlsLn.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("tls accept: %v", err)
			continue
		}
		s.wg.Add(1)
		go s.handleTLSConn(conn)
	}
}

// acceptExtra accepts connections on extra TCP ports (reach tests).
func (s *Server) acceptExtra(ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("extra accept: %v", err)
			continue
		}
		s.wg.Add(1)
		go s.handleExtraConn(conn, ln.Addr().(*net.TCPAddr).Port)
	}
}

// handleExtraConn reads the first JSON payload carrying a session and
// records a reach observation, replying {"ok":true}.
func (s *Server) handleExtraConn(conn net.Conn, dstPort int) {
	defer s.wg.Done()
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return
	}
	var m struct {
		Session string `json:"session"`
		Kind    string `json:"kind"`
	}
	raw := strings.TrimSpace(string(buf[:n]))
	if json.Unmarshal([]byte(raw), &m) != nil || !proto.ValidSessionID(m.Session) {
		_, _ = conn.Write([]byte(`{"ok":false}`))
		return
	}
	_, _ = conn.Write([]byte(`{"ok":true}`))

	obs := &proto.Obs{
		ID:      proto.NewID(),
		Kind:    proto.ObsTCP,
		Session: m.Session,
		DstPort: dstPort,
		Time:    time.Now(),
	}
	if host, port, err := splitHostPort(conn.RemoteAddr().String()); err == nil {
		obs.SrcIP, obs.SrcPort = host, port
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		if ti, err := tcpInfoFromConn(tc); err == nil {
			obs.TCPInfo = ti
		}
	}
	s.store.Append(m.Session, obs)
}

// gcLoop periodically removes expired sessions.
func (s *Server) gcLoop() {
	defer s.wg.Done()
	interval := s.cfg.TTL / 2
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.store.GC()
		}
	}
}

// --- HTTP handlers ---------------------------------------------------------

type connKey struct{}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.infoCache)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sess, ok := s.store.Get(id)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, sess.Obs)
}

// handleEcho records the server-side view of any non-API request: full
// headers (including any transparent-proxy injected headers), source
// address and TCP_INFO of the connection.
func (s *Server) handleEcho(w http.ResponseWriter, r *http.Request) {
	session := r.Header.Get("X-Netsee-Session")
	if !proto.ValidSessionID(session) {
		session = ""
	}
	obs := &proto.Obs{
		ID:      proto.NewID(),
		Kind:    proto.ObsHTTP,
		Session: session,
		DstPort: s.infoCache.HTTPPort,
		Time:    time.Now(),
		HTTP: &proto.HTTPObs{
			Method:  r.Method,
			Path:    r.URL.RequestURI(),
			Proto:   r.Proto,
			Headers: captureHeaders(r),
		},
	}
	if host, port, err := splitHostPort(r.RemoteAddr); err == nil {
		obs.SrcIP, obs.SrcPort = host, port
	}
	if ti := s.tcpInfo(r); ti != nil {
		obs.TCPInfo = ti
	}
	if session != "" {
		s.store.Append(session, obs)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "session": session, "obs_id": obs.ID})
}

func (s *Server) tcpInfo(r *http.Request) *proto.TCPInfo {
	c, ok := r.Context().Value(connKey{}).(net.Conn)
	if !ok {
		return nil
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil
	}
	ti, err := tcpInfoFromConn(tc)
	if err != nil {
		return nil
	}
	return ti
}

// captureHeaders returns Host followed by the remaining headers sorted by
// key: the full set of headers the probe received, in deterministic order.
func captureHeaders(r *http.Request) []proto.Header {
	out := make([]proto.Header, 0, len(r.Header)+1)
	out = append(out, proto.Header{Key: "Host", Value: r.Host})
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Header[k] {
			out = append(out, proto.Header{Key: k, Value: v})
		}
	}
	return out
}

// --- helpers ---------------------------------------------------------------

func splitHostPort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, n, nil
}

func parseIP(bind string) net.IP {
	if ip := net.ParseIP(bind); ip != nil {
		return ip
	}
	return nil // all interfaces
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// buildInfo derives the self-discovery response from the bound sockets.
func (s *Server) buildInfo() *proto.Info {
	extra := make([]int, 0, len(s.extraLn))
	for _, ln := range s.extraLn {
		if p, ok := ln.Addr().(*net.TCPAddr); ok {
			extra = append(extra, p.Port)
		}
	}
	info := &proto.Info{
		ProtocolVersion: "1",
		HTTPPort:        s.httpLn.Addr().(*net.TCPAddr).Port,
		TLSPort:         s.tlsLn.Addr().(*net.TCPAddr).Port,
		UDPPort:         s.udpLn.LocalAddr().(*net.UDPAddr).Port,
		NATPort:         s.natLn.LocalAddr().(*net.UDPAddr).Port,
		ExtraPorts:      extra,
		SecondIP:        s.cfg.SecondIP != "",
		SecondIPAddr:    s.cfg.SecondIP,
	}
	return info
}

// info returns the cached self-discovery info (valid after Start).
func (s *Server) info() *proto.Info { return s.infoCache }

// Ports returns the self-discovery info (valid after Start).
func (s *Server) Ports() *proto.Info { return s.infoCache }

// SessionCount returns the current number of live sessions.
func (s *Server) SessionCount() int { return s.store.Len() }

// GC forces an immediate session sweep (used by tests and observability).
func (s *Server) GC() { s.store.GC() }

// Shutdown stops accepting connections, drains in-flight handlers
// briefly, and waits for the serve loops to exit.
func (s *Server) Shutdown(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	default:
		close(s.done)
	}
	if s.httpSrv != nil {
		_ = s.httpSrv.Shutdown(ctx)
	}
	s.httpLn.Close()
	s.tlsLn.Close()
	s.udpLn.Close()
	s.natLn.Close()
	for _, ln := range s.extraLn {
		ln.Close()
	}
	s.wg.Wait()
	return nil
}
