package proto

import (
	"crypto/rand"
	"fmt"
)

// NewID returns a random UUID v4 string used for session and observation IDs.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is unrecoverable on supported platforms.
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ValidSessionID reports whether id looks like a session identifier:
// UUID v4 format (8-4-4-4-12) or a bare 32-character hex string.
func ValidSessionID(id string) bool {
	switch len(id) {
	case 36:
		for i := 0; i < len(id); i++ {
			c := id[i]
			switch i {
			case 8, 13, 18, 23:
				if c != '-' {
					return false
				}
			default:
				if !isHex(c) {
					return false
				}
			}
		}
		return true
	case 32:
		for i := 0; i < len(id); i++ {
			if !isHex(id[i]) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
