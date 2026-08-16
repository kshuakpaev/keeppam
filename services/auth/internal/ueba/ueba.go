package ueba

import "time"

const (
	FactorNewAsset = "ueba_new_asset"
	FactorSpread   = "ueba_spread"

	NewAssetPoints = 25
	SpreadPoints   = 20

	MinBaseline     = 3
	BaselineDays    = 30
	SpreadMinRecent = 6

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
