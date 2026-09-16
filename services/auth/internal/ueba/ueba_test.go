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

func TestFastMouseZ(t *testing.T) {
	z := ZScore(2.0, 0.4, 0.2)
	if z < MouseZThreshold {
		t.Fatalf("z=%v", z)
	}
	if !FastMouse(2.0, 50, 30, 5, 0.4, 0.2, z) {
		t.Fatal("expected fast mouse")
	}
	if FastMouse(0.4, 50, 30, 5, 0.4, 0.2, ZScore(0.4, 0.4, 0.2)) {
		t.Fatal("normal should not")
	}
}

func TestFastMouseColdStart(t *testing.T) {
	if !FastMouse(1.5, 50, 25, 0, 0, 0, 0) {
		t.Fatal("cold extreme")
	}
	if FastMouse(0.3, 50, 25, 0, 0, 0, 0) {
		t.Fatal("cold normal")
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

func TestUnusualHour(t *testing.T) {
	var hits [24]int
	for h := 9; h <= 17; h++ {
		hits[h] = 2
	}
	if !UnusualHour(hits, 3, 18) {
		t.Fatal("hour 03 should be unusual")
	}
	if UnusualHour(hits, 10, 18) {
		t.Fatal("hour 10 is in baseline")
	}
	if UnusualHour(hits, 3, 4) {
		t.Fatal("too few sessions")
	}
}
