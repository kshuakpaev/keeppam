package ueba

import "testing"

func TestFastTypingZ(t *testing.T) {
	z := ZScore(40, 180, 40)
	if z > KeystrokeZThreshold {
		t.Fatalf("z=%v want ≤ %v", z, KeystrokeZThreshold)
	}
	if !FastTyping(40, 30, 5, 180, 40, z) {
		t.Fatal("expected fast typing")
	}
	if FastTyping(180, 30, 5, 180, 40, ZScore(180, 180, 40)) {
		t.Fatal("normal should not fire")
	}
}

func TestFastTypingColdStart(t *testing.T) {
	if !FastTyping(40, 25, 0, 0, 0, 0) {
		t.Fatal("cold extreme should fire")
	}
	if FastTyping(120, 25, 0, 0, 0, 0) {
		t.Fatal("cold normal should not")
	}
	if FastTyping(40, 5, 0, 0, 0, 0) {
		t.Fatal("too few keys")
	}
}

func TestMeanStd(t *testing.T) {
	m, s := MeanStd([]float64{100, 200, 300})
	if m != 200 {
		t.Fatalf("mean=%v", m)
	}
	if s < 80 || s > 85 {
		t.Fatalf("std=%v", s)
	}
}
