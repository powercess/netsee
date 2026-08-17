package probe

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// --- ClientHello test builder ---------------------------------------------

type extEntry struct {
	typ  uint16
	data []byte
}

type helloBuilder struct {
	recordVersion uint16
	legacyVersion uint16
	sessionID     []byte
	ciphers       []uint16
	compressions  []byte
	extensions    []extEntry
}

func (b *helloBuilder) build() []byte {
	var body bytes.Buffer
	writeU16 := func(v uint16) {
		var tmp [2]byte
		binary.BigEndian.PutUint16(tmp[:], v)
		body.Write(tmp[:])
	}
	writeU16(b.legacyVersion)
	body.Write(make([]byte, 32)) // random
	body.WriteByte(byte(len(b.sessionID)))
	body.Write(b.sessionID)
	writeU16(uint16(2 * len(b.ciphers)))
	for _, c := range b.ciphers {
		writeU16(c)
	}
	body.WriteByte(byte(len(b.compressions)))
	body.Write(b.compressions)
	var ext bytes.Buffer
	for _, e := range b.extensions {
		var tmp [4]byte
		binary.BigEndian.PutUint16(tmp[0:2], e.typ)
		binary.BigEndian.PutUint16(tmp[2:4], uint16(len(e.data)))
		ext.Write(tmp[:])
		ext.Write(e.data)
	}
	writeU16(uint16(ext.Len()))
	body.Write(ext.Bytes())

	var hs bytes.Buffer
	hs.WriteByte(tlsHandshakeClientHello)
	l := body.Len()
	hs.WriteByte(byte(l >> 16))
	hs.WriteByte(byte(l >> 8))
	hs.WriteByte(byte(l))
	hs.Write(body.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(tlsContentHandshake)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], b.recordVersion)
	rec.Write(tmp[:])
	binary.BigEndian.PutUint16(tmp[:], uint16(hs.Len()))
	rec.Write(tmp[:])
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

// u16 builds a 2-byte-length-prefixed list of uint16 values.
func u16(vals ...uint16) []byte {
	b := make([]byte, 2+2*len(vals))
	binary.BigEndian.PutUint16(b, uint16(2*len(vals)))
	for i, v := range vals {
		binary.BigEndian.PutUint16(b[2+2*i:], v)
	}
	return b
}

// u8list16 builds a 1-byte-length-prefixed list of uint16 values.
func u8list16(vals ...uint16) []byte {
	b := make([]byte, 1+2*len(vals))
	b[0] = byte(2 * len(vals))
	for i, v := range vals {
		binary.BigEndian.PutUint16(b[1+2*i:], v)
	}
	return b
}

func u8list(vals ...byte) []byte {
	b := make([]byte, 1+len(vals))
	b[0] = byte(len(vals))
	copy(b[1:], vals)
	return b
}

func sniExt(name string) extEntry {
	inner := make([]byte, 3+len(name))
	inner[0] = 0 // host_name
	binary.BigEndian.PutUint16(inner[1:3], uint16(len(name)))
	copy(inner[3:], name)
	data := make([]byte, 2+len(inner))
	binary.BigEndian.PutUint16(data, uint16(len(inner)))
	copy(data[2:], inner)
	return extEntry{extSNI, data}
}

func alpnExt(vals ...string) extEntry {
	var body []byte
	for _, v := range vals {
		body = append(body, byte(len(v)))
		body = append(body, v...)
	}
	data := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(data, uint16(len(body)))
	copy(data[2:], body)
	return extEntry{extALPN, data}
}

func sigAlgsExt(vals ...uint16) extEntry { return extEntry{extSigAlgs, u16(vals...)} }
func groupsExt(vals ...uint16) extEntry  { return extEntry{extSupportedGroups, u16(vals...)} }
func pointFormatsExt(vals ...byte) extEntry {
	return extEntry{extECPointFormats, u8list(vals...)}
}
func suppVersionsExt(vals ...uint16) extEntry {
	return extEntry{extSupportedVersion, u8list16(vals...)}
}
func rawExt(typ uint16) extEntry { return extEntry{typ, nil} }

func parseHello(t *testing.T, raw []byte) *clientHello {
	t.Helper()
	p := &helloParser{}
	ch, complete, err := p.Feed(raw)
	if !complete || err != nil {
		t.Fatalf("parse failed: complete=%v err=%v", complete, err)
	}
	return ch
}

// --- Fixed vectors (published answers) -------------------------------------

// JA3 vector 1: salesforce/ja3 README example
// "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
// -> ada70206e40642a3e4461f35503241d5
func buildJA3Vector1() *helloBuilder {
	return &helloBuilder{
		recordVersion: 0x0301,
		legacyVersion: 0x0301,
		compressions:  []byte{0x00},
		ciphers: []uint16{
			0x002f, 0x0035, 0x0005, 0x000a, 0xc009, 0xc00a, 0xc013, 0xc014,
			0x0032, 0x0038, 0x0013, 0x0004,
		},
		extensions: []extEntry{
			sniExt("example.com"),
			groupsExt(0x0017, 0x0018, 0x0019),
			pointFormatsExt(0x00),
		},
	}
}

// JA3 vector 2: salesforce/ja3 README example, no extensions
// "769,4-5-10-9-100-98-3-6-19-18-99,,,"
// -> de350869b8c85de67a350c8d186f11e6
func buildJA3Vector2() *helloBuilder {
	return &helloBuilder{
		recordVersion: 0x0301,
		legacyVersion: 0x0301,
		compressions:  []byte{0x00},
		ciphers: []uint16{
			0x0004, 0x0005, 0x000a, 0x0009, 0x0064, 0x0062,
			0x0003, 0x0006, 0x0013, 0x0012, 0x0063,
		},
	}
}

// JA4 vector: FoxIO JA4 spec example
// -> t13d1516h2_8daaf6152771_e5627efa2ab1
func buildJA4Vector() *helloBuilder {
	return &helloBuilder{
		recordVersion: 0x0301,
		legacyVersion: 0x0303,
		compressions:  []byte{0x00},
		ciphers: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
			0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		extensions: []extEntry{
			rawExt(0x001b),
			sniExt("example.com"),
			rawExt(0x0033),
			alpnExt("h2"),
			rawExt(0x4469),
			rawExt(0x0017),
			rawExt(0x002d),
			sigAlgsExt(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601),
			rawExt(0x0005),
			rawExt(0x0023),
			rawExt(0x0012),
			suppVersionsExt(0x0304),
			rawExt(0xff01),
			pointFormatsExt(0x00),
			groupsExt(0x0017, 0x0018, 0x0019),
			rawExt(0x0015),
		},
	}
}

const (
	wantJA3Vector1 = "ada70206e40642a3e4461f35503241d5"
	wantJA3Vector2 = "de350869b8c85de67a350c8d186f11e6"
	wantJA4Vector  = "t13d1516h2_8daaf6152771_e5627efa2ab1"
)

func TestJA3FixedVector1(t *testing.T) {
	ch := parseHello(t, buildJA3Vector1().build())
	if got := ch.JA3(); got != wantJA3Vector1 {
		t.Errorf("JA3 = %s, want %s", got, wantJA3Vector1)
	}
}

func TestJA3FixedVector2(t *testing.T) {
	ch := parseHello(t, buildJA3Vector2().build())
	if got := ch.JA3(); got != wantJA3Vector2 {
		t.Errorf("JA3 = %s, want %s", got, wantJA3Vector2)
	}
}

func TestJA4FixedVector(t *testing.T) {
	ch := parseHello(t, buildJA4Vector().build())
	if got := ch.JA4(); got != wantJA4Vector {
		t.Errorf("JA4 = %s, want %s", got, wantJA4Vector)
	}
}

// --- Fragmentation ---------------------------------------------------------

func TestParseFragmentedByteByByte(t *testing.T) {
	raw := buildJA4Vector().build()
	p := &helloParser{}
	for i := 0; i < len(raw); i++ {
		_, complete, err := p.Feed(raw[i : i+1])
		if i < len(raw)-1 {
			if complete || err != nil {
				t.Fatalf("premature completion at byte %d: complete=%v err=%v", i, complete, err)
			}
			continue
		}
		if !complete || err != nil {
			t.Fatalf("final byte: complete=%v err=%v", complete, err)
		}
	}
}

func TestParseFragmentedEverySplit(t *testing.T) {
	raw := buildJA4Vector().build()
	for split := 1; split < len(raw); split++ {
		p := &helloParser{}
		if _, complete, err := p.Feed(raw[:split]); complete || err != nil {
			t.Fatalf("split %d first half: complete=%v err=%v", split, complete, err)
		}
		ch, complete, err := p.Feed(raw[split:])
		if !complete || err != nil {
			t.Fatalf("split %d second half: complete=%v err=%v", split, complete, err)
		}
		if got := ch.JA4(); got != wantJA4Vector {
			t.Fatalf("split %d JA4 = %s, want %s", split, got, wantJA4Vector)
		}
		if got := ch.JA3(); got == "" {
			t.Fatalf("split %d: empty JA3", split)
		}
	}
}

// --- GREASE ----------------------------------------------------------------

func TestGREASEIgnored(t *testing.T) {
	// GREASE cipher values, GREASE values inside supported_groups, and
	// GREASE extension types must not affect the fingerprint.
	base := buildJA3Vector1()
	greased := buildJA3Vector1()
	greased.ciphers = append([]uint16{0x0a0a}, greased.ciphers...)
	greased.ciphers = append(greased.ciphers, 0xfafa)
	greased.extensions[1] = groupsExt(0x0a0a, 0x0017, 0x0018, 0x0019)
	greased.extensions = append(greased.extensions, rawExt(0x1a1a), rawExt(0xaaaa))

	chBase := parseHello(t, base.build())
	chGreased := parseHello(t, greased.build())
	if chBase.JA3() != chGreased.JA3() {
		t.Errorf("JA3 changed with GREASE: %s vs %s", chBase.JA3(), chGreased.JA3())
	}
	if chBase.JA4() != chGreased.JA4() {
		t.Errorf("JA4 changed with GREASE: %s vs %s", chBase.JA4(), chGreased.JA4())
	}

	// GREASE in supported_versions values must not leak into the version
	// field; the extension type itself is real, so only the version check
	// applies here.
	sv := buildJA3Vector1()
	sv.extensions = append(sv.extensions, suppVersionsExt(0xaaaa))
	ch := parseHello(t, sv.build())
	if got := ch.JA4(); len(got) < 4 || got[1:3] != "10" {
		t.Errorf("JA4 version should fall back to legacy 10, got %q", got)
	}
}

// --- Malformed input -------------------------------------------------------

func TestParseMalformed(t *testing.T) {
	cases := []struct {
		name     string
		raw      []byte
		needMore bool
	}{
		{"wrong content type", []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01}, false},
		{"truncated record header", []byte{0x16, 0x03}, true},
		{"wrong handshake type", []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x01}, false},
		{"garbage", []byte("not a tls handshake at all, just text"), false},
		{"empty", nil, true},
	}
	for _, tc := range cases {
		p := &helloParser{}
		ch, complete, err := p.Feed(tc.raw)
		if tc.needMore {
			if complete {
				t.Errorf("%s: expected needMore, got complete", tc.name)
			}
			continue
		}
		if !complete || err == nil {
			t.Errorf("%s: expected invalid, got complete=%v ch=%v err=%v", tc.name, complete, ch != nil, err)
		}
	}
}

func TestParseOversized(t *testing.T) {
	p := &helloParser{}
	_, complete, err := p.Feed(make([]byte, maxHelloBytes+1))
	if !complete || err == nil {
		t.Fatalf("oversized feed: complete=%v err=%v", complete, err)
	}
	// parser resets: a valid hello after garbage still parses
	ch, complete, err := p.Feed(buildJA3Vector1().build())
	if !complete || err != nil || ch.JA3() != wantJA3Vector1 {
		t.Fatalf("parser not reset after overflow: complete=%v err=%v", complete, err)
	}
}
