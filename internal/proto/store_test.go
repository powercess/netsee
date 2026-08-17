package proto

import (
	"testing"
	"time"
)

func TestValidSessionID(t *testing.T) {
	valid := []string{
		"01234567-89ab-cdef-0123-456789abcdef",
		"0123456789abcdef0123456789abcdef",
		"DEADBEEF-0000-4000-8000-0123456789ab",
	}
	for _, id := range valid {
		if !ValidSessionID(id) {
			t.Errorf("ValidSessionID(%q) = false, want true", id)
		}
	}
	invalid := []string{
		"",
		"abc",
		"01234567-89ab-cdef-0123-456789abcde",  // 37 chars
		"01234567-89ab-cdef-0123-456789abc",    // 35 chars
		"zzzzzzzz-89ab-cdef-0123-456789abcdef", // non-hex
		"01234567_89ab-cdef-0123-456789abcdef", // wrong separator
		"0123456789abcdef0123456789abcdeg",     // non-hex 32
	}
	for _, id := range invalid {
		if ValidSessionID(id) {
			t.Errorf("ValidSessionID(%q) = true, want false", id)
		}
	}
}

func TestNewID(t *testing.T) {
	id := NewID()
	if !ValidSessionID(id) {
		t.Fatalf("NewID() = %q, not a valid session ID", id)
	}
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		nid := NewID()
		if seen[nid] {
			t.Fatalf("duplicate ID %q", nid)
		}
		seen[nid] = true
	}
}

func TestAppendGet(t *testing.T) {
	s := NewStore(time.Minute, 100)
	obs := &Obs{ID: NewID(), Kind: ObsHTTP}
	sess := NewID()
	if !s.Append(sess, obs) {
		t.Fatal("Append rejected valid session")
	}
	got, ok := s.Get(sess)
	if !ok {
		t.Fatal("Get failed for stored session")
	}
	if len(got.Obs) != 1 {
		t.Fatalf("got %d obs, want 1", len(got.Obs))
	}
	// invalid and unknown IDs
	if s.Append("not-valid", obs) {
		t.Error("Append accepted invalid session ID")
	}
	if _, ok := s.Get("not-valid"); ok {
		t.Error("Get accepted invalid session ID")
	}
	if _, ok := s.Get(NewID()); ok {
		t.Error("Get returned unknown session")
	}
}

func TestStoreTTLExpiry(t *testing.T) {
	now := time.Now()
	s := NewStore(100*time.Millisecond, 100)
	s.now = func() time.Time { return now }
	sess := NewID()
	s.Append(sess, &Obs{ID: NewID()})

	now = now.Add(50 * time.Millisecond)
	if _, ok := s.Get(sess); !ok {
		t.Fatal("session expired too early")
	}
	now = now.Add(100 * time.Millisecond)
	if _, ok := s.Get(sess); ok {
		t.Fatal("session should be expired after TTL")
	}
	// expired read deletes; Len back to zero
	if s.Len() != 0 {
		t.Fatalf("Len = %d after expiry, want 0", s.Len())
	}
}

func TestStoreGC(t *testing.T) {
	now := time.Now()
	s := NewStore(time.Minute, 100)
	s.now = func() time.Time { return now }
	a, b := NewID(), NewID()
	s.Append(a, &Obs{ID: NewID()})
	s.Append(b, &Obs{ID: NewID()})
	now = now.Add(2 * time.Minute)
	s.GC()
	if s.Len() != 0 {
		t.Fatalf("Len = %d after GC, want 0", s.Len())
	}
}

func TestStoreMaxSessionsEviction(t *testing.T) {
	s := NewStore(time.Hour, 2)
	ids := []string{NewID(), NewID(), NewID()}
	for _, id := range ids {
		s.Append(id, &Obs{ID: NewID()})
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (cap enforced)", s.Len())
	}
	// oldest (ids[0]) must be evicted
	if _, ok := s.Get(ids[0]); ok {
		t.Error("oldest session not evicted")
	}
}

func TestObsCapPerSession(t *testing.T) {
	s := NewStore(time.Hour, 10)
	sess := NewID()
	for i := 0; i < maxObsPerSession+100; i++ {
		s.Append(sess, &Obs{ID: NewID()})
	}
	got, _ := s.Get(sess)
	if len(got.Obs) != maxObsPerSession {
		t.Fatalf("obs = %d, want cap %d", len(got.Obs), maxObsPerSession)
	}
}
