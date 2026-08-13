package obs

import (
	"sort"
	"time"
)

const (
	AuthP95Target         = 500 * time.Millisecond
	SessionSetupP95Target = 2 * time.Second
	AuditLagTarget        = 60 * time.Second
)

func Quantile(samples []float64, q float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	s := append([]float64(nil), samples...)
	sort.Float64s(s)
	if q <= 0 {
		return s[0]
	}
	if q >= 1 {
		return s[len(s)-1]
	}
	idx := q * float64(len(s)-1)
	lo := int(idx)
	hi := lo + 1
	if hi >= len(s) {
		return s[lo]
	}
	frac := idx - float64(lo)
	return s[lo]*(1-frac) + s[hi]*frac
}

func Burn(observed, target float64) float64 {
	if target <= 0 {
		return 0
	}
	return observed / target
}

func Breached(observed *float64, target float64, samples int) bool {
	if observed == nil || samples == 0 {
		return false
	}
	return *observed > target
}
