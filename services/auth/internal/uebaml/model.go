package uebaml

import "math"

const (
	FactorPeerOutlier = "ueba_peer_outlier"
	FactorMLHigh      = "ueba_ml_high"
	FactorLiveFast    = "ueba_live_fast"

	PeerOutlierPoints = 20
	MLHighPoints      = 25
	LiveFastPoints    = 20

	DefaultThreshold = 65
	MinPeerMembers   = 5
	PeerRareRatio    = 0.10
)

// Features is the on-prem feature vector (no external ML runtime).
type Features struct {
	UnusualAsset  float64
	SpreadBurst   float64
	FailedLogins  float64
	Concurrent    float64
	PeerAssetRare float64 // 1 - fraction of peers who touched this asset
	OffHours      float64
	KeystrokeZ    float64 // negative = faster than baseline
	MouseZ        float64
}

// MLScore returns 0..100 composite behavior score.
func MLScore(f Features) float64 {
	raw := 0.0
	raw += 25 * clamp01(f.UnusualAsset)
	raw += 20 * clamp01(f.SpreadBurst)
	raw += 15 * clamp01(f.FailedLogins)
	raw += 10 * clamp01(f.Concurrent / 3)
	raw += 20 * clamp01(f.PeerAssetRare)
	raw += 10 * clamp01(f.OffHours)
	if f.KeystrokeZ < 0 {
		raw += 15 * clamp01(-f.KeystrokeZ / 3)
	}
	if f.MouseZ > 0 {
		raw += 10 * clamp01(f.MouseZ / 3)
	}
	return math.Min(100, raw)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
