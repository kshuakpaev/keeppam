package sshproxy

import (
	"strings"
	"unicode"

	"github.com/keeppam/auth/internal/termcharset"
)

// CommandGuard buffers a line of input and decides allow/deny via AllowFn.
type CommandGuard struct {
	AllowFn func(line string) bool
	// Notify is called immediately (e.g. newline before a blocking AllowFn).
	Notify  func([]byte)
	Charset string
	buf     []byte
}

func NewCommandGuard(allow func(line string) bool) *CommandGuard {
	return &CommandGuard{AllowFn: allow}
}

func (g *CommandGuard) echoNow(echo *[]byte, p ...byte) {
	if g.Notify != nil {
		g.Notify(p)
		return
	}
	*echo = append(*echo, p...)
}

// Feed processes raw PTY input. Returns (forward, echo, deniedLine).
// forward is written to remote stdin; echo is shown locally (when remote ECHO is off).
// AllowFn / denied see UTF-8 (charset-decoded); remote still receives original bytes.
func (g *CommandGuard) Feed(p []byte) (forward, echo []byte, denied string) {
	if g == nil || g.AllowFn == nil {
		return p, nil, ""
	}
	for _, b := range p {
		switch b {
		case '\r', '\n':
			raw := append([]byte(nil), g.buf...)
			g.buf = g.buf[:0]
			g.echoNow(&echo, '\r', '\n')
			if len(raw) == 0 || strings.TrimSpace(string(raw)) == "" {
				forward = append(forward, '\n')
				continue
			}
			line := termcharset.Decode(raw, g.Charset).Text
			if g.AllowFn(line) {
				forward = append(forward, raw...)
				forward = append(forward, '\n')
			} else {
				denied = line
			}
		case 0x7f, 0x08: // DEL / BS
			if len(g.buf) > 0 {
				g.buf = g.buf[:len(g.buf)-1]
				g.echoNow(&echo, 0x08, ' ', 0x08)
			}
		default:
			if unicode.IsPrint(rune(b)) || b == '\t' || b >= 0x80 {
				g.buf = append(g.buf, b)
				g.echoNow(&echo, b)
			}
		}
	}
	return forward, echo, denied
}
