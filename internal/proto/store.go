package proto

import (
	"sync"
	"time"
)

// maxObsPerSession bounds observations stored per session (defensive cap
// against an uncooperative client filling memory through one session).
const maxObsPerSession = 4096

// Session groups observations for one measurement session.
type Session struct {
	ID      string
	Created time.Time
	Obs     []*Obs
}

// Store is an in-memory session registry with TTL cleanup. It never
// touches disk (NFR-SEC-001).
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
	ttl      time.Duration
	max      int
	now      func() time.Time
}

// NewStore creates a registry. A ttl <= 0 disables expiry; max <= 0
// disables the session cap.
func NewStore(ttl time.Duration, max int) *Store {
	return &Store{
		sessions: make(map[string]*Session),
		ttl:      ttl,
		max:      max,
		now:      time.Now,
	}
}

// Append records obs under session, creating the session if unknown.
// Invalid or empty session IDs are rejected and obs is not stored.
func (s *Store) Append(session string, obs *Obs) bool {
	if !ValidSessionID(session) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	sess, ok := s.sessions[session]
	if !ok {
		if s.max > 0 && len(s.sessions) >= s.max {
			s.evictExpiredLocked(now)
			if len(s.sessions) >= s.max {
				s.evictOldestLocked()
			}
		}
		sess = &Session{ID: session, Created: now}
		s.sessions[session] = sess
	}
	if len(sess.Obs) < maxObsPerSession {
		sess.Obs = append(sess.Obs, obs)
	}
	return true
}

// Get returns a snapshot of the session if present and not expired.
// Unknown and expired sessions are indistinguishable (both return false).
func (s *Store) Get(id string) (*Session, bool) {
	if !ValidSessionID(id) {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	if s.ttl > 0 && s.now().Sub(sess.Created) > s.ttl {
		delete(s.sessions, id)
		return nil, false
	}
	snap := &Session{ID: sess.ID, Created: sess.Created, Obs: append([]*Obs(nil), sess.Obs...)}
	return snap, true
}

// Len returns the number of live sessions.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// GC removes expired sessions.
func (s *Store) GC() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked(s.now())
}

func (s *Store) evictExpiredLocked(now time.Time) {
	if s.ttl <= 0 {
		return
	}
	for id, sess := range s.sessions {
		if now.Sub(sess.Created) > s.ttl {
			delete(s.sessions, id)
		}
	}
}

func (s *Store) evictOldestLocked() {
	var oldestID string
	var oldestTime time.Time
	first := true
	for id, sess := range s.sessions {
		if first || sess.Created.Before(oldestTime) {
			oldestID, oldestTime, first = id, sess.Created, false
		}
	}
	if !first {
		delete(s.sessions, oldestID)
	}
}
