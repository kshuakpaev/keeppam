package guacindex

import (
	"bufio"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

// MouseTiming is pointer-move velocity stats from Guacamole mouse opcodes (px/ms).
type MouseTiming struct {
	NMoves    int     `json:"n_moves"`
	MedianVel float64 `json:"median_vel_px_ms"`
	MeanVel   float64 `json:"mean_vel_px_ms"`
	Samples   int     `json:"samples"`
}

const (
	minMouseDistPx = 8.0
	minMouseDtMs   = 5.0
	maxMouseDtMs   = 2000.0
	maxMouseSamp   = 8000
)

// ParseKeysMouseAndTiming extracts key lines, key IKI, and mouse move velocities in one pass.
func ParseKeysMouseAndTiming(r io.Reader) ([]Line, Timing, MouseTiming, error) {
	br := bufio.NewReader(io.LimitReader(r, MaxBytes))
	var buf strings.Builder
	var lastOff float64
	var out []Line
	var intervals []float64
	var lastPressMs float64
	var hasPress bool
	nKeys := 0

	var vel []float64
	nMoves := 0
	var lastX, lastY, lastMs float64
	hasPos := false

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
			case "mouse":
				if len(inst) >= 4 && len(vel) < maxMouseSamp {
					x, e1 := strconv.ParseFloat(inst[2], 64)
					y, e2 := strconv.ParseFloat(inst[3], 64)
					if e1 == nil && e2 == nil {
						ms := lastOff * 1000
						nMoves++
						if hasPos {
							dt := ms - lastMs
							dist := math.Hypot(x-lastX, y-lastY)
							if dt >= minMouseDtMs && dt <= maxMouseDtMs && dist >= minMouseDistPx {
								vel = append(vel, dist/dt)
							}
						}
						lastX, lastY, lastMs = x, y, ms
						hasPos = true
					}
				}
			}
		}
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				return finish(out, &buf, lastOff), summarizeTiming(nKeys, intervals), summarizeMouse(nMoves, vel), err
			}
			break
		}
		if len(out) >= MaxLines && len(vel) >= maxMouseSamp {
			break
		}
	}
	return finish(out, &buf, lastOff), summarizeTiming(nKeys, intervals), summarizeMouse(nMoves, vel), nil
}

func summarizeMouse(nMoves int, vel []float64) MouseTiming {
	t := MouseTiming{NMoves: nMoves, Samples: len(vel)}
	if len(vel) == 0 {
		return t
	}
	sum := 0.0
	for _, v := range vel {
		sum += v
	}
	t.MeanVel = sum / float64(len(vel))
	sorted := append([]float64(nil), vel...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		t.MedianVel = (sorted[mid-1] + sorted[mid]) / 2
	} else {
		t.MedianVel = sorted[mid]
	}
	if math.IsNaN(t.MedianVel) {
		t.MedianVel = 0
	}
	return t
}
