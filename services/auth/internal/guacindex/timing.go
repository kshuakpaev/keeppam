package guacindex

import (
	"bufio"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
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
	br := bufio.NewReader(io.LimitReader(r, MaxBytes))
	var buf strings.Builder
	var lastOff float64
	var out []Line
	var intervals []float64
	var lastPressMs float64
	var hasPress bool
	nKeys := 0
	for {
		inst, err := readInstruction(br)
		if len(inst) > 0 {
			switch inst[0] {
			case "sync":
				if len(inst) > 1 {
					if ms, e := strconv.ParseFloat(inst[1], 64); e == nil {
						lastOff = ms / 1000.0
					}
				}
			case "key":
				if len(inst) >= 3 && inst[2] == "1" {
					ks, _ := strconv.Atoi(inst[1])
					pressMs := lastOff * 1000
					if hasPress {
						d := pressMs - lastPressMs
						if d >= minIKIMs && d <= maxIKIMs {
							intervals = append(intervals, d)
						}
					}
					lastPressMs = pressMs
					hasPress = true
					nKeys++
					out = applyKey(out, &buf, lastOff, ks)
				}
			}
		}
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				return finish(out, &buf, lastOff), summarizeTiming(nKeys, intervals), err
			}
			break
		}
		if len(out) >= MaxLines {
			break
		}
	}
	return finish(out, &buf, lastOff), summarizeTiming(nKeys, intervals), nil
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
