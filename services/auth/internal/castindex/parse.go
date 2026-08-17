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
	in, _, err := ParseCast(r)
	return in, err
}

// ParseCast extracts stdin ("i") and stdout ("o") lines from asciicast v2.
func ParseCast(r io.Reader) (in, out []Line, err error) {
	br := bufio.NewReader(io.LimitReader(r, MaxBytes))
	var inBuf, outBuf strings.Builder
	var inOff, outOff float64
	first := true
	for {
		raw, err := br.ReadBytes('\n')
		if len(raw) > 0 {
			line := strings.TrimRight(string(raw), "\r\n")
			if line != "" {
				if first && strings.HasPrefix(strings.TrimSpace(line), "{") {
					first = false
				} else {
					first = false
					off, kind, data, ok := parseCastEvent(line)
					if ok {
						switch kind {
						case "i":
							inOff = off
							in = appendRunes(in, &inBuf, inOff, data, false)
						case "o":
							outOff = off
							out = appendRunes(out, &outBuf, outOff, data, true)
						}
					}
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return in, out, err
		}
		if len(in) >= MaxLines && len(out) >= MaxLines {
			break
		}
	}
	if t := flushLine(&inBuf, false); t != "" && len(in) < MaxLines {
		in = append(in, Line{Offset: inOff, Text: t})
	}
	if t := flushLine(&outBuf, true); t != "" && len(out) < MaxLines {
		if !dupLast(out, t) {
			out = append(out, Line{Offset: outOff, Text: t})
		}
	}
	if in == nil {
		in = []Line{}
	}
	if out == nil {
		out = []Line{}
	}
	return in, out, nil
}

func appendRunes(dst []Line, buf *strings.Builder, off float64, data string, output bool) []Line {
	for _, ch := range data {
		if len(dst) >= MaxLines {
			return dst
		}
		switch ch {
		case '\r', '\n':
			if t := flushLine(buf, output); t != "" {
				if output && dupLast(dst, t) {
					continue
				}
				dst = append(dst, Line{Offset: off, Text: t})
			}
		default:
			buf.WriteRune(ch)
		}
	}
	return dst
}

func flushLine(buf *strings.Builder, output bool) string {
	t := CleanLine(buf.String())
	buf.Reset()
	if output && !keepOutput(t) {
		return ""
	}
	return t
}

func dupLast(dst []Line, t string) bool {
	return len(dst) > 0 && dst[len(dst)-1].Text == t
}

func keepOutput(s string) bool {
	if s == "" {
		return false
	}
	switch s {
	case "$", "#", "%", ">", "~", "$$":
		return false
	}
	return true
}

func parseCastEvent(line string) (float64, string, string, bool) {
	var rec []json.RawMessage
	if json.Unmarshal([]byte(line), &rec) != nil || len(rec) < 3 {
		return 0, "", "", false
	}
	var kind string
	if json.Unmarshal(rec[1], &kind) != nil {
		return 0, "", "", false
	}
	if kind != "i" && kind != "o" {
		return 0, "", "", false
	}
	var off float64
	_ = json.Unmarshal(rec[0], &off)
	var data string
	if json.Unmarshal(rec[2], &data) != nil {
		return 0, "", "", false
	}
	return off, kind, data, true
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
