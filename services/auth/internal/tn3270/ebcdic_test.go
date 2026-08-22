package tn3270

import "testing"

func TestEBCDICRoundTrip(t *testing.T) {
	s := "KeepPAM 3270"
	b := EncodeEBCDIC(s)
	got := DecodeEBCDIC(b)
	if got != s {
		t.Fatalf("got %q want %q", got, s)
	}
}

func TestSplitEOR(t *testing.T) {
	payload := []byte{0xF5, 0xC3, 0x40}
	framed := FrameEOR(payload)
	frames, rest := SplitEOR(framed)
	if len(rest) != 0 || len(frames) != 1 {
		t.Fatalf("frames=%d rest=%d", len(frames), len(rest))
	}
	if string(frames[0]) != string(payload) {
		t.Fatalf("%v vs %v", frames[0], payload)
	}
}

func TestSplitEOREscapedFF(t *testing.T) {
	payload := []byte{0x40, 0xFF, 0x40}
	framed := FrameEOR(payload)
	frames, _ := SplitEOR(framed)
	if len(frames) != 1 || string(frames[0]) != string(payload) {
		t.Fatalf("%v", frames)
	}
}

func TestExtractScreenTextLatin(t *testing.T) {
	stream := []byte{0xF5, 0xC3, 0x11, 0x40, 0x40, 0x1D, 0x60}
	stream = append(stream, EncodeEBCDIC("ABC")...)
	got := ExtractScreenText(stream, CP037)
	if got != "ABC" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractScreenTextDBCS_GE(t *testing.T) {
	// EW + WCC + SBA + SF + GE + カ (cp930 0x4283)
	stream := []byte{0xF5, 0xC3, 0x11, 0x40, 0x40, 0x1D, 0x60, 0x08, 0x42, 0x83}
	got := ExtractScreenText(stream, CP930)
	if got != "カ" {
		t.Fatalf("got %q want カ", got)
	}
}

func TestDecodeBytesDBCSPair(t *testing.T) {
	got := DecodeBytes([]byte{0x42, 0x83}, CP930)
	if got != "カ" {
		t.Fatalf("got %q", got)
	}
}

func TestDefaultTermType(t *testing.T) {
	if DefaultTermType(CP933) != "IBM-3278-5" {
		t.Fatal("kr term")
	}
	if DefaultTermType(CP939) != "IBM-3279-4" {
		t.Fatal("jp term")
	}
}

func TestResolveTermTypeOverride(t *testing.T) {
	got := ResolveTermType("IBM-3278-4", CP930)
	if got != "IBM-3278-4" {
		t.Fatalf("got %s", got)
	}
}
