package ueba

import "testing"

func TestNewAsset(t *testing.T) {
	if NewAsset(2, false) {
		t.Fatal("cold start must not fire")
	}
	if NewAsset(3, true) {
		t.Fatal("usual asset must not fire")
	}
	if !NewAsset(3, false) {
		t.Fatal("4th host against a 3-asset baseline must fire")
	}
}

func TestSpread(t *testing.T) {
	if Spread(3, 4) {
		t.Fatal("4 in a day is new-asset, not spread")
	}
	if !Spread(3, 6) {
		t.Fatal("6 vs usual 3 must fire")
	}
	if Spread(8, 12) {
		t.Fatal("12 vs usual 8 is not 2×")
	}
	if Spread(2, 12) {
		t.Fatal("no baseline → no spread")
	}
}
