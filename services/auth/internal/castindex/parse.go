package castindex

import (
	"bufio"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxBytes = 8 << 20
	MaxLines = 400
	MaxLine  = 512
)

var csiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b.`)

type Line struct {
	Offset float64
	Text   string
}

// InputLines extracts typed SSH lines from an asciicast v2 stream (event type "i").
func InputLines(r io.Reader) ([]Line, error) {
	br := bufio.NewReader(io.LimitReader(r, MaxBytes))
	var buf strings.Builder
	var lastOff float64
	var out []Line
	first := true
	for {
		if len(out) >= MaxLines {
			break
		}
		raw, err := br.ReadBytes('\n')
		if len(raw) > 0 {
			line := strings.TrimRight(string(raw), "\r\n")
			if line != "" {
				if first && strings.HasPrefix(strings.TrimSpace(line), "{") {
					first = false
				} else {
					first = false
					off, data, ok := parseInputEvent(line)
					if ok {
						lastOff = off
						for _, ch := range data {
							switch ch {
							case '\r', '\n':
								if t := CleanLine(buf.String()); t != "" {
									out = append(out, Line{Offset: lastOff, Text: t})
									if len(out) >= MaxLines {
										return out, err
									}
								}
								buf.Reset()
							default:
								buf.WriteRune(ch)
							}
						}
					}
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return out, err
		}
	}
	if t := CleanLine(buf.String()); t != "" && len(out) < MaxLines {
		out = append(out, Line{Offset: lastOff, Text: t})
	}
	if out == nil {
		out = []Line{}
	}
	return out, nil
}

func parseInputEvent(line string) (float64, string, bool) {
	var rec []json.RawMessage
	if json.Unmarshal([]byte(line), &rec) != nil || len(rec) < 3 {
		return 0, "", false
	}
	var kind string
	if json.Unmarshal(rec[1], &kind) != nil || kind != "i" {
		return 0, "", false
	}
	var off float64
	_ = json.Unmarshal(rec[0], &off)
	var data string
	if json.Unmarshal(rec[2], &data) != nil {
		return 0, "", false
	}
	return off, data, true
}

func CleanLine(s string) string {
	s = csiRe.ReplaceAllString(s, "")
	var b strings.Builder
	for _, r := range s {
		if r == '\t' || unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	s = strings.TrimSpace(b.String())
	if s == "" {
		return ""
	}
	if utf8.RuneCountInString(s) > MaxLine {
		rs := []rune(s)
		s = string(rs[:MaxLine])
	}
	return s
}
