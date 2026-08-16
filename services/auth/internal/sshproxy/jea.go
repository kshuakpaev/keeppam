package sshproxy

import (
	"strings"
	"unicode"
)

// CommandGuard buffers a line of input and decides allow/deny via AllowFn.
type CommandGuard struct {
	AllowFn func(line string) bool
	// Notify is called immediately (e.g. newline before a blocking AllowFn).
	Notify func([]byte)
	buf    []byte
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
func (g *CommandGuard) Feed(p []byte) (forward, echo []byte, denied string) {
	if g == nil || g.AllowFn == nil {
		return p, nil, ""
	}
	for _, b := range p {
		switch b {
		case '\r', '\n':
			line := string(g.buf)
			g.buf = g.buf[:0]
			g.echoNow(&echo, '\r', '\n')
			if strings.TrimSpace(line) == "" {
				forward = append(forward, '\n')
				continue
			}
			if g.AllowFn(line) {
				forward = append(forward, []byte(line)...)
				forward = append(forward, '\n')
			} else {
				denied = line
			}
		case 0x7f, 0x08: // DEL / BS
			if len(g.buf) > 0 {
				g.buf = g.buf[:len(g.buf)-1]
				g.echoNow(&echo, 0x08, ' ', 0x08)
			}
		case 0x03: // Ctrl-C
			g.buf = g.buf[:0]
			forward = append(forward, 0x03)
			g.echoNow(&echo, '^', 'C', '\r', '\n')
		case 0x04: // Ctrl-D
			forward = append(forward, 0x04)
		default:
			if b == 0x1b { // ESC sequences — pass through to remote (arrows etc. break JEA line model)
				forward = append(forward, b)
				continue
			}
			if unicode.IsPrint(rune(b)) || b == '\t' {
				g.buf = append(g.buf, b)
				g.echoNow(&echo, b)
			}
		}
	}
	return forward, echo, denied
}
