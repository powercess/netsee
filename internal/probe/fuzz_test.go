package probe

import (
	"testing"

	"netsee/internal/proto"
)

// FuzzUDPPayload asserts the UDP payload parser never panics and only
// returns ok for valid session IDs. Run: go test -fuzz=FuzzUDPPayload ./internal/probe/
func FuzzUDPPayload(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"session":"01234567-89ab-cdef-0123-456789abcdef","kind":"echo"}`),
		[]byte(`{"session":"0123456789abcdef0123456789abcdef","kind":"nat"}`),
		[]byte(`garbage`),
		[]byte(`{"session":123,"kind":"echo"}`),
		{0xff, 0x00, 0x01},
		{},
		make([]byte, 4096),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		session, _, ok := parseUDPPayload(data)
		if ok && !proto.ValidSessionID(session) {
			t.Fatalf("parse ok but session invalid: %q", session)
		}
	})
}

// FuzzClientHello asserts the TLS ClientHello parser never panics on any
// input. Run: go test -fuzz=FuzzClientHello ./internal/probe/
func FuzzClientHello(f *testing.F) {
	f.Add(buildJA4Vector().build())
	f.Add(buildJA3Vector1().build())
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01})
	f.Add([]byte("not a tls handshake"))
	f.Add(make([]byte, 512))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := &helloParser{}
		_, _, _ = p.Feed(data)
	})
}
