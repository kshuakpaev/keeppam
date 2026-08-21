package ueba

import (
	"math"
	"time"
)

const (
	FactorNewAsset       = "ueba_new_asset"
	FactorSpread         = "ueba_spread"
	FactorKeystrokeFast  = "ueba_keystroke_fast"
	FactorKeystrokeStats = "keystroke_stats"
	FactorMouseFast      = "ueba_mouse_fast"
	FactorMouseStats     = "mouse_stats"

	NewAssetPoints      = 25
	SpreadPoints        = 20
	KeystrokeFastPoints = 30
	MouseFastPoints     = 25

	MinBaseline     = 3
	BaselineDays    = 30
	SpreadMinRecent = 6

	MinKeystrokeKeys     = 20
	MinKeystrokeBaseline = 3
	KeystrokeZThreshold  = -2.0 // median much faster than baseline
	KeystrokeAbsFastMs   = 55   // absolute floor when no baseline yet but very fast

	MinMouseMoves      = 40
	MinMouseBaseline   = 3
	MinMouseSamples    = 20
	MouseZThreshold    = 2.0 // median velocity much higher than baseline
	MouseAbsFastVel    = 1.2 // px/ms cold-start (~1200 px/s)

	// SessionSQL is a fragment for historical sessions that count toward baseline.
	SessionSQL = `status IN ('pending','active','ended')`
)

func BaselineFrom(now time.Time) time.Time {
	return now.UTC().Add(-time.Duration(BaselineDays) * 24 * time.Hour)
}

// NewAsset is true when the user already has a stable set of assets and this one is not in it.
func NewAsset(baselineDistinct int, seenCurrent bool) bool {
	return baselineDistinct >= MinBaseline && !seenCurrent
}

// Spread is true when a day's distinct assets is at least twice the 30-day set and not a small blip.
func Spread(baselineDistinct, last24hDistinct int) bool {
	if baselineDistinct < MinBaseline {
		return false
	}
	return last24hDistinct >= SpreadMinRecent && last24hDistinct >= baselineDistinct*2
}

// ZScore returns (x-mean)/std; std<=0 → 0.
func ZScore(x, mean, std float64) float64 {
	if std <= 1e-9 {
		return 0
	}
	z := (x - mean) / std
	if math.IsNaN(z) || math.IsInf(z, 0) {
		return 0
	}
	return z
}

// FastTyping is true when typing is anomalously fast vs baseline (z ≤ threshold)
// or, without enough baseline, median is below absolute floor with enough keys.
func FastTyping(medianMs float64, nKeys int, baselineN int, mean, std, z float64) bool {
	if nKeys < MinKeystrokeKeys || medianMs <= 0 {
		return false
	}
	if baselineN >= MinKeystrokeBaseline && std > 0 {
		return z <= KeystrokeZThreshold
	}
	// Cold start: only flag extreme absolute speed (bot-like).
	return medianMs <= KeystrokeAbsFastMs
}

// FastMouse is true when pointer velocity is anomalously high vs baseline (z ≥ threshold)
// or, without enough baseline, median velocity exceeds absolute floor.
func FastMouse(medianVel float64, nMoves, samples, baselineN int, mean, std, z float64) bool {
	if nMoves < MinMouseMoves || samples < MinMouseSamples || medianVel <= 0 {
		return false
	}
	if baselineN >= MinMouseBaseline && std > 0 {
		return z >= MouseZThreshold
	}
	return medianVel >= MouseAbsFastVel
}

// MeanStd of a sample (population std).
func MeanStd(vals []float64) (mean, std float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	mean = sum / float64(len(vals))
	if len(vals) < 2 {
		return mean, 0
	}
	var ss float64
	for _, v := range vals {
		d := v - mean
		ss += d * d
	}
	std = math.Sqrt(ss / float64(len(vals)))
	return mean, std
}
