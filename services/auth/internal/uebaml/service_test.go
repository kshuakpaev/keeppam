package uebaml

import (
	"testing"
)

func TestMLScore(t *testing.T) {
	s := MLScore(Features{UnusualAsset: 1, PeerAssetRare: 0.9, OffHours: 1})
	if s < 50 {
		t.Fatalf("expected high score, got %v", s)
	}
	low := MLScore(Features{})
	if low != 0 {
		t.Fatalf("empty features: %v", low)
	}
}

func TestPeerOutlier(t *testing.T) {
	if !peerOutlier(0.05, 10) {
		t.Fatal("expected outlier")
	}
	if peerOutlier(0.5, 10) {
		t.Fatal("common asset")
	}
	if peerOutlier(0.01, 3) {
		t.Fatal("too few peers")
	}
}

func TestNormalizeMode(t *testing.T) {
	if _, err := NormalizeMode("bad"); err == nil {
		t.Fatal("bad mode")
	}
	m, _ := NormalizeMode("live")
	if m != "live" {
		t.Fatal(m)
	}
}
