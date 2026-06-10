package codec

import (
	"bytes"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	salt := bytes.Repeat([]byte{0xFF}, 128)
	srcIP := []byte{10, 0, 0, 1}
	dstIP := []byte{10, 0, 1, 1}

	data := Encode(42, salt, 1700000000000000000, 256,
		srcIP, dstIP, 43600, 43600,
		5000, 43600, 43600)

	if !IsValid(data) {
		t.Fatal("IsValid returned false for valid packet")
	}

	r := Decode(data)
	if r.Seq != 42 {
		t.Fatalf("Seq: got %d, want 42", r.Seq)
	}
	if r.Ts != 1700000000000000000 {
		t.Fatalf("Ts: got %d, want 1700000000000000000", r.Ts)
	}
	if r.LastSentCount != 5000 {
		t.Fatalf("LastSentCount: got %d, want 5000", r.LastSentCount)
	}
	if !bytes.Equal(r.SrcIP, srcIP) {
		t.Fatalf("SrcIP: got %v, want %v", r.SrcIP, srcIP)
	}
	if !bytes.Equal(r.DstIP, dstIP) {
		t.Fatalf("DstIP: got %v, want %v", r.DstIP, dstIP)
	}
	if r.SrcPort != 43600 {
		t.Fatalf("SrcPort: got %d, want 43600", r.SrcPort)
	}
	if r.DstPort != 43600 {
		t.Fatalf("DstPort: got %d, want 43600", r.DstPort)
	}
	if r.LastStartSrcPort != 43600 {
		t.Fatalf("LastStartSrcPort: got %d, want 43600", r.LastStartSrcPort)
	}
	if r.LastStartDstPort != 43600 {
		t.Fatalf("LastStartDstPort: got %d, want 43600", r.LastStartDstPort)
	}

	// Check salt padding (first 128 bytes are 0xFF, remaining salt area is zero-filled)
	if !bytes.Equal(data[MsgHeaderLen:MsgHeaderLen+128], bytes.Repeat([]byte{0xFF}, 128)) {
		t.Fatal("salt padding mismatch")
	}
}

func TestIsValidTooShort(t *testing.T) {
	short := []byte("KUINIUTC")
	if IsValid(short) {
		t.Fatal("IsValid should return false for short data")
	}
}

func TestIsValidWrongMagic(t *testing.T) {
	data := make([]byte, MsgHeaderLen+10)
	copy(data, []byte("WRONGMAG"))
	if IsValid(data) {
		t.Fatal("IsValid should return false for wrong magic")
	}
}

func TestDecodeTooShort(t *testing.T) {
	r := Decode([]byte("KUINIUTC"))
	if r.Seq != 0 || r.Ts != 0 {
		t.Fatal("Decode should return zero values for short data")
	}
}

func TestMsgHeaderLen(t *testing.T) {
	// magic(8) + seq(8) + ts(8) + lastSent(4) + srcIP(4) + dstIP(4) + srcPort(2) + dstPort(2) + lssp(2) + lsdp(2) = 44
	if MsgHeaderLen != 44 {
		t.Fatalf("MsgHeaderLen = %d, want 44", MsgHeaderLen)
	}
}

func TestEncodeMinimumLength(t *testing.T) {
	salt := []byte{0xAA}
	srcIP := []byte{192, 168, 1, 1}
	dstIP := []byte{192, 168, 1, 2}

	data := Encode(1, salt, 123, 0, srcIP, dstIP, 1234, 5678, 100, 1234, 5678)
	if len(data) != MsgHeaderLen {
		t.Fatalf("minimum length packet: got %d, want %d", len(data), MsgHeaderLen)
	}
	if !IsValid(data) {
		t.Fatal("minimum length packet should be valid")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	salt := bytes.Repeat([]byte{0x5A}, 200)
	srcIP := []byte{172, 16, 0, 100}
	dstIP := []byte{172, 16, 1, 200}

	for _, msgLen := range []int{64, 128, 512, 1024} {
		data := Encode(999, salt, 9876543210, msgLen,
			srcIP, dstIP, 44000, 44001,
			4999, 44000, 44001)

		if !IsValid(data) {
			t.Fatalf("msgLen=%d: IsValid false", msgLen)
		}
		r := Decode(data)
		if r.Seq != 999 {
			t.Fatalf("msgLen=%d: Seq mismatch", msgLen)
		}
		if r.Ts != 9876543210 {
			t.Fatalf("msgLen=%d: Ts mismatch", msgLen)
		}
		if !bytes.Equal(r.SrcIP, srcIP) {
			t.Fatalf("msgLen=%d: SrcIP mismatch", msgLen)
		}
		if !bytes.Equal(r.DstIP, dstIP) {
			t.Fatalf("msgLen=%d: DstIP mismatch", msgLen)
		}
		if r.SrcPort != 44000 || r.DstPort != 44001 {
			t.Fatalf("msgLen=%d: port mismatch", msgLen)
		}
	}
}
