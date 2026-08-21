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

func TestExtractScreenText(t *testing.T) {
	// EW + WCC + SBA + SF + "ABC"
	stream := []byte{0xF5, 0xC3, 0x11, 0x40, 0x40, 0x1D, 0x60}
	stream = append(stream, EncodeEBCDIC("ABC")...)
	got := ExtractScreenText(stream)
	if got != "ABC" {
		t.Fatalf("got %q", got)
	}
}
