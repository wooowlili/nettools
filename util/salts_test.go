package util

import (
	"bytes"
	"testing"
)

func TestNewSalts_PatternsAndLength(t *testing.T) {
	const n = 16
	s := NewSalts(n)

	cases := []struct {
		name string
		seq  uint64
		want []byte
	}{
		{"all-ones", 0, bytes.Repeat([]byte{0xFF}, n)},
		{"all-zeros", 1, bytes.Repeat([]byte{0x00}, n)},
		{"0x5A", 2, bytes.Repeat([]byte{0x5A}, n)},
		{"complementary", 3, ComplementaryBytes(n)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.Get(c.seq)
			if len(got) != n {
				t.Fatalf("len = %d, want %d", len(got), n)
			}
			if !bytes.Equal(got, c.want) {
				t.Errorf("salt = % x, want % x", got, c.want)
			}
		})
	}
}

func TestSalts_GetCyclesBySeqMod4(t *testing.T) {
	s := NewSalts(8)
	for seq := uint64(0); seq < 32; seq++ {
		got := s.Get(seq)
		want := s.Get(seq % 4)
		if !bytes.Equal(got, want) {
			t.Errorf("seq=%d: salt = % x, want % x", seq, got, want)
		}
	}
}

func TestSalts_GetReturnsLiveSlice(t *testing.T) {
	s := NewSalts(4)
	a := s.Get(0)
	b := s.Get(0)
	if &a[0] != &b[0] {
		t.Errorf("Get should return the same backing array on repeated calls")
	}
}

func TestSalts_CheckBitflip(t *testing.T) {
	s := NewSalts(8)
	salt := s.Get(0)

	matching := append([]byte(nil), salt...)
	if s.CheckBitflip(matching, salt) {
		t.Error("equal payloads must not be flagged as bit-flip")
	}

	flipped := append([]byte(nil), salt...)
	flipped[3] ^= 0x01
	if !s.CheckBitflip(flipped, salt) {
		t.Error("single-bit flip must be detected")
	}

	short := salt[:len(salt)-1]
	if !s.CheckBitflip(short, salt) {
		t.Error("length mismatch must be flagged")
	}

	if !s.CheckBitflip(nil, salt) {
		t.Error("nil payload must be flagged")
	}
}

func TestComplementaryBytes_Pattern(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{}},
		{1, []byte{0xAA}},
		{2, []byte{0xAA, 0xAA}},
		{3, []byte{0xAA, 0xAA, 0x55}},
		{4, []byte{0xAA, 0xAA, 0x55, 0x55}},
		{5, []byte{0xAA, 0xAA, 0x55, 0x55, 0xAA}},
		{8, []byte{0xAA, 0xAA, 0x55, 0x55, 0xAA, 0xAA, 0x55, 0x55}},
	}
	for _, c := range cases {
		got := ComplementaryBytes(c.n)
		if !bytes.Equal(got, c.want) {
			t.Errorf("ComplementaryBytes(%d) = % x, want % x", c.n, got, c.want)
		}
	}
}

func TestComplementaryBytes_AdjacentWordsAreComplements(t *testing.T) {
	const n = 64
	b := ComplementaryBytes(n)
	for i := 0; i+3 < n; i += 4 {
		w1 := uint16(b[i])<<8 | uint16(b[i+1])
		w2 := uint16(b[i+2])<<8 | uint16(b[i+3])
		if w1^w2 != 0xFFFF {
			t.Errorf("offset %d: words %04x and %04x are not complementary", i, w1, w2)
		}
	}
}

func TestNewSalts_ZeroLen(t *testing.T) {
	s := NewSalts(0)
	for seq := uint64(0); seq < 4; seq++ {
		if got := s.Get(seq); len(got) != 0 {
			t.Errorf("seq=%d: len = %d, want 0", seq, len(got))
		}
	}
	if s.CheckBitflip([]byte{}, s.Get(0)) {
		t.Error("two empty slices must not be flagged as bit-flip")
	}
}
