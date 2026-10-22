package mesh

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeData(t *testing.T) {
	p := bytes.Repeat([]byte{0xab}, 10)
	f := EncodeData(0x01020304, p)
	if !bytes.Equal(f[:4], []byte{1, 2, 3, 4}) || !bytes.Equal(f[4:], p) {
		t.Fatalf("frame %x", f)
	}
	id, got, ok := DecodeData(f)
	if !ok || id != 0x01020304 || !bytes.Equal(got, p) {
		t.Fatalf("decode %d %x %v", id, got, ok)
	}
	if _, got, ok := DecodeData(EncodeData(7, nil)); !ok || len(got) != 0 {
		t.Fatal("empty payload is a valid frame")
	}
	if _, _, ok := DecodeData([]byte{0, 0, 1}); ok {
		t.Fatal("short frame accepted")
	}
	if _, _, ok := DecodeData([]byte{0, 0, 0, 0, 1}); ok {
		t.Fatal("stream id zero accepted")
	}
	if _, _, ok := DecodeData(EncodeData(1, make([]byte, MaxPayload))); !ok {
		t.Fatal("max payload refused")
	}
	if _, _, ok := DecodeData(append(EncodeData(1, make([]byte, MaxPayload)), 0)); ok {
		t.Fatal("oversized payload accepted")
	}
}

func TestCredit(t *testing.T) {
	c := NewCredit(100)
	if c.Sendable(1000) != 100 || c.Sendable(10) != 10 {
		t.Fatal("sendable")
	}
	if !c.Take(60) || c.Sendable(1000) != 40 || c.Take(41) || !c.Take(40) || c.Sendable(1) != 0 {
		t.Fatal("take")
	}
	if c.Grant(0) || c.Grant(-1) || c.Grant(101) {
		t.Fatal("bad grants accepted")
	}
	if !c.Grant(100) || c.Grant(1) {
		t.Fatal("grant past window accepted")
	}
	// Receiving side: quarter-window batching.
	r := NewCredit(100)
	if !r.Receive(100) || r.Receive(1) {
		t.Fatal("receive overrun accepted")
	}
	if r.Drain(10) != 0 || r.Drain(10) != 0 || r.Drain(5) != 25 {
		t.Fatal("drain batching")
	}
	if !r.Receive(25) {
		t.Fatal("credit was not returned to the window")
	}
	if r.Drain(100) != 100 { // capped at inWindow
		t.Fatal("drain cap")
	}
	if r.Flush() != 0 || r.Drain(0) != 0 || r.Drain(-3) != 0 {
		t.Fatal("flush/drain zero")
	}
	if NewCredit(0).Window() != 1 {
		t.Fatal("min window")
	}
}

func TestStatusError(t *testing.T) {
	if (&StatusError{}).Error() != "internal" || (&StatusError{Code: "x"}).Error() != "x" {
		t.Fatal("codes")
	}
}
