package guacindex

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxBytes = 8 << 20
	MaxLines = 400
	MaxLine  = 512
	maxArg   = 64 << 10
)

type Line struct {
	Offset float64
	Text   string
}

// ParseKeys extracts typed lines from a Guacamole session recording (opcode "key").
func ParseKeys(r io.Reader) ([]Line, error) {
	br := bufio.NewReader(io.LimitReader(r, MaxBytes))
	var buf strings.Builder
	var lastOff float64
	var out []Line
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
				// Guacamole: key,keysym,pressed (pressed is 1/0).
				if len(inst) >= 3 && inst[2] == "1" {
					ks, _ := strconv.Atoi(inst[1])
					out = applyKey(out, &buf, lastOff, ks)
				}
			}
		}
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				return finish(out, &buf, lastOff), err
			}
			break
		}
		if len(out) >= MaxLines {
			break
		}
	}
	return finish(out, &buf, lastOff), nil
}

func finish(out []Line, buf *strings.Builder, off float64) []Line {
	if t := cleanLine(buf.String()); t != "" && len(out) < MaxLines {
		if !dupLast(out, t) {
			out = append(out, Line{Offset: off, Text: t})
		}
	}
	if out == nil {
		out = []Line{}
	}
	return out
}

func applyKey(out []Line, buf *strings.Builder, off float64, ks int) []Line {
	if len(out) >= MaxLines {
		return out
	}
	switch ks {
	case 0xff0d, 0xff8d: // Return / KP_Enter
		if t := cleanLine(buf.String()); t != "" {
			if !dupLast(out, t) {
				out = append(out, Line{Offset: off, Text: t})
			}
		}
		buf.Reset()
		return out
	case 0xff08: // BackSpace
		s := buf.String()
		if s == "" {
			return out
		}
		_, size := utf8.DecodeLastRuneInString(s)
		buf.Reset()
		buf.WriteString(s[:len(s)-size])
		return out
	case 0xff09: // Tab
		buf.WriteByte('\t')
		return out
	}
	if r, ok := keysymRune(ks); ok {
		buf.WriteRune(r)
	}
	return out
}

func keysymRune(ks int) (rune, bool) {
	if ks >= 0x01000000 {
		r := rune(ks & 0x00ffffff)
		return r, unicode.IsPrint(r) || r == '\t'
	}
	if ks >= 0x20 && ks <= 0xff {
		return rune(ks), true
	}
	return 0, false
}

func cleanLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
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

func dupLast(dst []Line, t string) bool {
	return len(dst) > 0 && dst[len(dst)-1].Text == t
}

func readInstruction(br *bufio.Reader) ([]string, error) {
	var args []string
	for {
		n, err := readLength(br)
		if err != nil {
			return args, err
		}
		if n < 0 {
			continue
		}
		var val string
		if n > maxArg {
			_, _ = io.CopyN(io.Discard, br, int64(n))
		} else {
			buf := make([]byte, n)
			if _, err := io.ReadFull(br, buf); err != nil {
				return args, err
			}
			val = string(buf)
		}
		sep, err := br.ReadByte()
		if err != nil {
			return append(args, val), err
		}
		args = append(args, val)
		if sep == ';' {
			return args, nil
		}
		if sep != ',' {
			return args, skipToSemi(br)
		}
	}
}

func readLength(br *bufio.Reader) (int, error) {
	var digits strings.Builder
	for {
		c, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		if c >= '0' && c <= '9' {
			digits.WriteByte(c)
			continue
		}
		if c == '.' && digits.Len() > 0 {
			n, err := strconv.Atoi(digits.String())
			if err != nil || n < 0 {
				return 0, skipToSemi(br)
			}
			return n, nil
		}
		if c == ';' && digits.Len() == 0 {
			return -1, nil
		}
		return 0, skipToSemi(br)
	}
}

func skipToSemi(br *bufio.Reader) error {
	for {
		c, err := br.ReadByte()
		if err != nil {
			return err
		}
		if c == ';' {
			return nil
		}
	}
}
