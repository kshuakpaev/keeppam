package hdx

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"
)

// ParseJSONL reads Citrix HDX recording events from a KeepPAM JSONL file.
func ParseJSONL(path string) ([]RecordingEvt, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []RecordingEvt
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		ev := RecordingEvt{
			T:     strField(raw["t"]),
			Event: strField(raw["event"]),
			Seq:   intField(raw["seq"]),
		}
		if m, ok := raw["meta"].(map[string]any); ok {
			ev.Meta = m
		}
		if ev.Event == "" {
			continue
		}
		out = append(out, NormalizeEvt(ev))
	}
	return out, sc.Err()
}

func strField(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func intField(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	default:
		return 0
	}
}

func MetaFloat(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	switch n := m[key].(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case string:
		f, _ := strconv.ParseFloat(n, 64)
		return f
	default:
		return 0
	}
}

func MetaString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	return strField(m[key])
}

func ParseTime(t string, fallback time.Time) time.Time {
	if t == "" {
		return fallback
	}
	if ts, err := time.Parse(time.RFC3339Nano, t); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse(time.RFC3339, t); err == nil {
		return ts.UTC()
	}
	return fallback
}
