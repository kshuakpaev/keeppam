package obs

import (
	"math"
	"testing"
)

func TestQuantileEmpty(t *testing.T) {
	if Quantile(nil, 0.95) != 0 {
		t.Fatal("empty")
	}
}

func TestQuantileP95(t *testing.T) {
	s := make([]float64, 100)
	for i := range s {
		s[i] = float64(i + 1)
	}
	got := Quantile(s, 0.95)
	if math.Abs(got-95.05) > 0.2 && math.Abs(got-95) > 0.2 {
		t.Fatalf("p95=%v", got)
	}
}

func TestQuantileSingle(t *testing.T) {
	if Quantile([]float64{0.4}, 0.95) != 0.4 {
		t.Fatal("single")
	}
}

func TestBurn(t *testing.T) {
	if Burn(1, 0.5) != 2 {
		t.Fatal("burn")
	}
	if Burn(0.25, 0.5) != 0.5 {
		t.Fatal("under")
	}
}

func TestBreached(t *testing.T) {
	v := 0.6
	if !Breached(&v, 0.5, 10) {
		t.Fatal("should breach")
	}
	if Breached(&v, 0.5, 0) {
		t.Fatal("no samples")
	}
	if Breached(nil, 0.5, 10) {
		t.Fatal("nil")
	}
	ok := 0.1
	if Breached(&ok, 0.5, 3) {
		t.Fatal("under target")
	}
}
