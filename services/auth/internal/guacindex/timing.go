package guacindex

import (
	"io"
	"math"
	"sort"
)

// Timing is inter-key interval stats from Guacamole key presses (ms).
type Timing struct {
	NKeys     int     `json:"n_keys"`
	MedianMs  float64 `json:"median_iki_ms"`
	MeanMs    float64 `json:"mean_iki_ms"`
	Intervals int     `json:"intervals"`
}

const (
	minIKIMs = 15
	maxIKIMs = 3000
)

// ParseKeysAndTiming extracts typed lines and inter-key intervals from a Guac recording.
func ParseKeysAndTiming(r io.Reader) ([]Line, Timing, error) {
	lines, keys, _, err := ParseKeysMouseAndTiming(r)
	return lines, keys, err
}

// ParseKeys extracts typed lines from a Guacamole session recording (opcode "key").
func ParseKeys(r io.Reader) ([]Line, error) {
	lines, _, err := ParseKeysAndTiming(r)
	return lines, err
}

func summarizeTiming(nKeys int, intervals []float64) Timing {
	t := Timing{NKeys: nKeys, Intervals: len(intervals)}
	if len(intervals) == 0 {
		return t
	}
	sum := 0.0
	for _, v := range intervals {
		sum += v
	}
	t.MeanMs = sum / float64(len(intervals))
	sorted := append([]float64(nil), intervals...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		t.MedianMs = (sorted[mid-1] + sorted[mid]) / 2
	} else {
		t.MedianMs = sorted[mid]
	}
	if math.IsNaN(t.MedianMs) {
		t.MedianMs = 0
	}
	return t
}
