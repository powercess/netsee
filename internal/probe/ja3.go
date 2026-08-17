package probe

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// TLS record/handshake constants needed for ClientHello parsing.
const (
	tlsContentHandshake     = 22
	tlsHandshakeClientHello = 1

	extSNI              = 0x0000
	extSupportedGroups  = 0x000a
	extECPointFormats   = 0x000b
	extSigAlgs          = 0x000d
	extALPN             = 0x0010
	extSupportedVersion = 0x002b
)

// maxHelloBytes caps the accumulated ClientHello buffer; larger inputs
// are treated as not-a-ClientHello (defensive limit, THR-PROBE-001).
const maxHelloBytes = 64 * 1024

// clientHello holds the fields required for JA3/JA4 computation.
type clientHello struct {
	legacyVersion uint16
	ciphers       []uint16
	extensions    []uint16
	extData       map[uint16][]byte
	sni           string
	alpn          []string
	sigAlgs       []uint16
	suppVersions  []uint16
	groups        []uint16
	pointFormats  []byte
}

// isGREASE reports whether v is a GREASE value (RFC 8701).
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a }

// parse state
const (
	stateNeedMore = iota
	stateDone
	stateInvalid
)

// helloParser accumulates TLS bytes from a stream and parses the first
// ClientHello once complete. TCP fragmentation at any byte boundary is
// handled by buffering until the handshake length is satisfied.
type helloParser struct {
	buf []byte
}

// Feed adds bytes and attempts parsing.
//
//   - (nil, false, nil): need more bytes.
//   - (ch, true, nil): ClientHello parsed successfully.
//   - (nil, true, err): bytes are not a parseable ClientHello; the parser
//     is reset and further feeds will start fresh.
func (p *helloParser) Feed(b []byte) (*clientHello, bool, error) {
	if len(p.buf)+len(b) > maxHelloBytes {
		p.buf = p.buf[:0]
		return nil, true, errNotClientHello
	}
	p.buf = append(p.buf, b...)
	ch, state := parseClientHello(p.buf)
	switch state {
	case stateDone:
		p.buf = p.buf[:0]
		return ch, true, nil
	case stateInvalid:
		p.buf = p.buf[:0]
		return nil, true, errNotClientHello
	default:
		return nil, false, nil
	}
}

var errNotClientHello = fmt.Errorf("not a ClientHello")

// parseClientHello parses a TLS record containing a ClientHello.
// Returns stateNeedMore when the buffer is incomplete.
func parseClientHello(b []byte) (*clientHello, int) {
	if len(b) < 5 {
		return nil, stateNeedMore
	}
	if b[0] != tlsContentHandshake {
		return nil, stateInvalid
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 4 {
		return nil, stateInvalid
	}
	if len(b) < 5+recLen {
		return nil, stateNeedMore
	}
	hb := b[5 : 5+recLen]
	if hb[0] != tlsHandshakeClientHello {
		return nil, stateInvalid
	}
	hsLen := int(hb[1])<<16 | int(hb[2])<<8 | int(hb[3])
	if len(hb) < 4+hsLen {
		return nil, stateNeedMore
	}
	return parseClientHelloBody(hb[4 : 4+hsLen])
}

// parseClientHelloBody parses the ClientHello body and derives the
// extension payloads needed for JA3/JA4. Every read is bounds-checked;
// malformed input returns stateInvalid.
func parseClientHelloBody(body []byte) (*clientHello, int) {
	ch := &clientHello{extData: make(map[uint16][]byte)}
	if len(body) < 2+32+1+2+1+2 {
		return nil, stateInvalid
	}
	pos := 0
	ch.legacyVersion = binary.BigEndian.Uint16(body[pos:])
	pos += 2 + 32 // legacy_version + random

	sidLen := int(body[pos])
	pos++
	if pos+sidLen > len(body) {
		return nil, stateInvalid
	}
	pos += sidLen

	if pos+2 > len(body) {
		return nil, stateInvalid
	}
	cipherLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	if cipherLen < 2 || cipherLen%2 != 0 || pos+cipherLen > len(body) {
		return nil, stateInvalid
	}
	for i := 0; i < cipherLen; i += 2 {
		ch.ciphers = append(ch.ciphers, binary.BigEndian.Uint16(body[pos+i:]))
	}
	pos += cipherLen

	if pos >= len(body) {
		return nil, stateInvalid
	}
	compLen := int(body[pos])
	pos++
	if compLen < 1 || pos+compLen > len(body) {
		return nil, stateInvalid
	}
	pos += compLen

	if pos+2 > len(body) {
		return nil, stateInvalid
	}
	extLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	if pos+extLen > len(body) {
		return nil, stateInvalid
	}
	extEnd := pos + extLen
	for pos < extEnd {
		if pos+4 > extEnd {
			return nil, stateInvalid
		}
		typ := binary.BigEndian.Uint16(body[pos:])
		l := int(binary.BigEndian.Uint16(body[pos+2:]))
		pos += 4
		if pos+l > extEnd {
			return nil, stateInvalid
		}
		ch.extensions = append(ch.extensions, typ)
		ch.extData[typ] = body[pos : pos+l]
		pos += l
	}

	ch.sni = parseSNI(ch.extData[extSNI])
	ch.alpn = parseALPN(ch.extData[extALPN])
	ch.sigAlgs = parseUint16List2(ch.extData[extSigAlgs])
	ch.suppVersions = parseUint16List1(ch.extData[extSupportedVersion])
	ch.groups = parseUint16List2(ch.extData[extSupportedGroups])
	ch.pointFormats = parsePointFormats(ch.extData[extECPointFormats])
	return ch, stateDone
}

func parseSNI(d []byte) string {
	if len(d) < 2 {
		return ""
	}
	n := int(binary.BigEndian.Uint16(d))
	d = d[2:]
	if n > len(d) {
		return ""
	}
	pos := 0
	for pos < n {
		if pos+3 > n {
			return ""
		}
		typ := d[pos]
		l := int(binary.BigEndian.Uint16(d[pos+1:]))
		pos += 3
		if pos+l > n {
			return ""
		}
		if typ == 0 { // host_name
			return string(d[pos : pos+l])
		}
		pos += l
	}
	return ""
}

func parseALPN(d []byte) []string {
	if len(d) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(d))
	d = d[2:]
	if n > len(d) {
		return nil
	}
	var out []string
	pos := 0
	for pos < n {
		l := int(d[pos])
		pos++
		if pos+l > n {
			return nil
		}
		out = append(out, string(d[pos:pos+l]))
		pos += l
	}
	return out
}

// parseUint16List2 parses a 2-byte-length-prefixed list of uint16 values.
func parseUint16List2(d []byte) []uint16 {
	if len(d) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(d))
	d = d[2:]
	if n > len(d) || n%2 != 0 {
		return nil
	}
	out := make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		out = append(out, binary.BigEndian.Uint16(d[i:]))
	}
	return out
}

// parseUint16List1 parses a 1-byte-length-prefixed list of uint16 values.
func parseUint16List1(d []byte) []uint16 {
	if len(d) < 1 {
		return nil
	}
	n := int(d[0])
	d = d[1:]
	if n > len(d) || n%2 != 0 {
		return nil
	}
	out := make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		out = append(out, binary.BigEndian.Uint16(d[i:]))
	}
	return out
}

func parsePointFormats(d []byte) []byte {
	if len(d) < 1 {
		return nil
	}
	n := int(d[0])
	d = d[1:]
	if n > len(d) {
		return nil
	}
	return append([]byte(nil), d[:n]...)
}

// JA3 computes the JA3 fingerprint (salesforce/ja3 format):
// MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
// with GREASE values ignored. The version is the ClientHello legacy_version.
func (c *clientHello) JA3() string {
	var sb strings.Builder
	sb.WriteString(strconv.Itoa(int(c.legacyVersion)))
	sb.WriteByte(',')
	writeDecList(&sb, c.ciphers)
	sb.WriteByte(',')
	writeDecList(&sb, c.extensions)
	sb.WriteByte(',')
	writeDecList(&sb, c.groups)
	sb.WriteByte(',')
	writeByteDecList(&sb, c.pointFormats)
	sum := md5.Sum([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

func writeByteDecList(sb *strings.Builder, vals []byte) {
	for i, v := range vals {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(v)))
	}
}

func writeDecList(sb *strings.Builder, vals []uint16) {
	first := true
	for _, v := range vals {
		if isGREASE(v) {
			continue
		}
		if !first {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(v)))
		first = false
	}
}

// JA4 computes the JA4 fingerprint per the FoxIO spec:
// t<version><sni?><#ciphers><#extensions><alpn>_<cipher hash>_<ext+sigalgs hash>
// See docs and https://github.com/FoxIO-LLC/JA4.
func (c *clientHello) JA4() string {
	var a strings.Builder
	a.WriteByte('t')
	a.WriteString(ja4Version(c.suppVersions, c.legacyVersion))
	if c.sni != "" {
		a.WriteByte('d')
	} else {
		a.WriteByte('i')
	}
	a.WriteString(twoDigit(countNonGREASE(c.ciphers)))
	a.WriteString(twoDigit(countNonGREASE(c.extensions)))
	a.WriteString(ja4ALPN(c.alpn))

	a.WriteByte('_')
	a.WriteString(ja4Hash(ciphersHexSorted(c.ciphers)))

	a.WriteByte('_')
	a.WriteString(ja4ExtensionHash(c.extensions, c.sigAlgs))
	return a.String()
}

func countNonGREASE(vals []uint16) int {
	n := 0
	for _, v := range vals {
		if !isGREASE(v) {
			n++
		}
	}
	if n > 99 {
		return 99
	}
	return n
}

func twoDigit(n int) string {
	return fmt.Sprintf("%02d", n)
}

func ja4Version(vs []uint16, fallback uint16) string {
	ver := fallback
	for _, v := range vs {
		if !isGREASE(v) && v > ver {
			ver = v
		}
	}
	switch ver {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

// ja4ALPN returns the first and last ASCII alphanumeric characters of the
// first ALPN value; if they are not alphanumeric, the first and last hex
// characters of the value's hex representation ("00" when absent).
func ja4ALPN(vals []string) string {
	if len(vals) == 0 || vals[0] == "" {
		return "00"
	}
	v := vals[0]
	if isAlnum(v[0]) && isAlnum(v[len(v)-1]) {
		return string([]byte{v[0], v[len(v)-1]})
	}
	hs := hex.EncodeToString([]byte(v))
	return string([]byte{hs[0], hs[len(hs)-1]})
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// ciphersHexSorted returns non-GREASE ciphers as sorted 4-hex values,
// comma-delimited ("000000000000" semantics handled by ja4Hash).
func ciphersHexSorted(ciphers []uint16) string {
	var vals []string
	for _, c := range ciphers {
		if isGREASE(c) {
			continue
		}
		vals = append(vals, fmt.Sprintf("%04x", c))
	}
	sort.Strings(vals)
	return strings.Join(vals, ",")
}

// ja4ExtensionHash hashes the extension list (SNI and ALPN excluded,
// GREASE ignored, sorted) plus signature algorithms in order.
func ja4ExtensionHash(exts []uint16, sigAlgs []uint16) string {
	var vals []string
	for _, e := range exts {
		if isGREASE(e) || e == extSNI || e == extALPN {
			continue
		}
		vals = append(vals, fmt.Sprintf("%04x", e))
	}
	if len(vals) == 0 {
		return "000000000000"
	}
	sort.Strings(vals)
	s := strings.Join(vals, ",")
	if len(sigAlgs) > 0 {
		var algs []string
		for _, a := range sigAlgs {
			algs = append(algs, fmt.Sprintf("%04x", a))
		}
		s += "_" + strings.Join(algs, ",")
	}
	return ja4Hash(s)
}

// ja4Hash returns the first 12 hex chars of the sha256 of s;
// an empty input yields the explicit "000000000000" sentinel.
func ja4Hash(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
