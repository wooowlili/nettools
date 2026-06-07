// Package checksum provides deterministic salt generation and bit-flip detection
// for ICMP ping payloads. Mirrors the salt approach used by bitflip/bitflip6.
package checksum

import "bytes"

// Salt patterns chosen to expose different classes of bit-flip errors:
//   0: 0xFF — all bits set (any flip visible)
//   1: 0x00 — all bits clear (any flip visible)
//   2: 0x5A — alternating bit pattern (01011010)
//   3: complementary — 0xAAAA/0x5555 alternating 16-bit words (catches
//      complementary bit flips that TCP checksum cannot detect).

// Salts holds the four deterministic salt byte patterns indexed by seq % 4.
type Salts struct {
	salts [4][]byte
	msgLen int
}

// NewSalts creates the salt patterns for the given message size.
func NewSalts(msgLen int) *Salts {
	return &Salts{
		msgLen: msgLen,
		salts: [4][]byte{
			0: bytes.Repeat([]byte{0xFF}, msgLen),
			1: bytes.Repeat([]byte{0x00}, msgLen),
			2: bytes.Repeat([]byte{0x5A}, msgLen),
			3: complementaryBytes(msgLen),
		},
	}
}

// Get returns the salt pattern for the given sequence number.
func (s *Salts) Get(seq uint64) []byte {
	return s.salts[seq%4]
}

// CheckBitflip compares the received data against the expected salt.
// Returns true if any byte differs (bit-flip detected).
func (s *Salts) CheckBitflip(data, salt []byte) bool {
	return !bytes.Equal(data, salt)
}

// complementaryBytes generates the pattern: 0xAA 0xAA 0x55 0x55 repeating.
// Adjacent 16-bit words (0xAAAA, 0x5555) are bitwise complements, exposing
// the specific class of complementary bit flips that 1's complement checksum misses.
func complementaryBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		if (i/2)%2 == 0 {
			b[i] = 0xAA
		} else {
			b[i] = 0x55
		}
	}
	return b
}
