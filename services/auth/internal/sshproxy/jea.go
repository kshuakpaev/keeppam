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
	cursor  int    // byte index into buf
	esc     []byte // partial ANSI escape being collected
}

func NewCommandGuard(allow func(line string) bool) *CommandGuard {
	return &CommandGuard{AllowFn: allow}
}

func (g *CommandGuard) echoNow(echo *[]byte, p ...byte) {
	if len(p) == 0 {
		return
	}
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
		if len(g.esc) > 0 {
			g.esc = append(g.esc, b)
			if !g.finishEsc(&echo) {
				if len(g.esc) > 32 {
					g.esc = g.esc[:0]
				}
			}
			continue
		}
		switch b {
		case 0x1b: // ESC — start ANSI sequence (arrows etc.); never echo raw ESC/[…]
			g.esc = []byte{0x1b}
		case '\r', '\n':
			raw := append([]byte(nil), g.buf...)
			g.buf = g.buf[:0]
			g.cursor = 0
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
			g.backspace(&echo)
		case 0x01: // Ctrl+A — home
			g.moveHome(&echo)
		case 0x05: // Ctrl+E — end
			g.moveEnd(&echo)
		case 0x03: // Ctrl+C — clear line locally + forward to remote
			g.clearLine(&echo)
			forward = append(forward, 0x03)
		default:
			if unicode.IsPrint(rune(b)) || b == '\t' || b >= 0x80 {
				g.insert(b, &echo)
			}
			// other controls (except handled above) are ignored in JEA line mode
		}
	}
	return forward, echo, denied
}

// finishEsc returns true when the pending escape sequence was consumed.
func (g *CommandGuard) finishEsc(echo *[]byte) bool {
	if len(g.esc) < 2 {
		return false
	}
	switch g.esc[1] {
	case '[': // CSI: ESC [ … final(0x40–0x7E)
		if len(g.esc) < 3 {
			return false
		}
		last := g.esc[len(g.esc)-1]
		if last < 0x40 || last > 0x7e {
			return false
		}
		seq := g.esc
		g.esc = g.esc[:0]
		g.handleCSI(seq, echo)
		return true
	case 'O': // SS3 — application cursor keys
		if len(g.esc) < 3 {
			return false
		}
		key := g.esc[2]
		g.esc = g.esc[:0]
		switch key {
		case 'A', 'B': // up/down — no history yet
		case 'C':
			g.moveRight(echo)
		case 'D':
			g.moveLeft(echo)
		}
		return true
	default:
		// Unknown ESC-prefix: drop without echoing garbage.
		g.esc = g.esc[:0]
		return true
	}
}

func (g *CommandGuard) handleCSI(seq []byte, echo *[]byte) {
	if len(seq) < 3 {
		return
	}
	final := seq[len(seq)-1]
	switch final {
	case 'C': // right
		g.moveRight(echo)
	case 'D': // left
		g.moveLeft(echo)
	case 'A', 'B': // up/down — reserved (no command history yet)
	case 'H', 'F': // home / end (some terminals)
		if final == 'H' {
			g.moveHome(echo)
		} else {
			g.moveEnd(echo)
		}
	case '~': // extended keys e.g. \x1b[3~ delete, \x1b[1~ home
		body := string(seq[2 : len(seq)-1])
		switch body {
		case "3":
			g.deleteForward(echo)
		case "1", "7":
			g.moveHome(echo)
		case "4", "8":
			g.moveEnd(echo)
		}
	default:
		// discard unsupported CSI (do not echo "[D" etc.)
	}
}

func (g *CommandGuard) insert(b byte, echo *[]byte) {
	rest := append([]byte(nil), g.buf[g.cursor:]...)
	g.buf = append(g.buf[:g.cursor], b)
	g.buf = append(g.buf, rest...)
	g.cursor++
	g.echoNow(echo, b)
	if len(rest) == 0 {
		return
	}
	g.echoNow(echo, rest...)
	for range rest {
		g.echoNow(echo, 0x1b, '[', 'D')
	}
}

func (g *CommandGuard) backspace(echo *[]byte) {
	if g.cursor <= 0 {
		return
	}
	rest := append([]byte(nil), g.buf[g.cursor:]...)
	g.buf = append(g.buf[:g.cursor-1], rest...)
	g.cursor--
	g.echoNow(echo, 0x08, ' ', 0x08)
	if len(rest) == 0 {
		return
	}
	g.echoNow(echo, rest...)
	g.echoNow(echo, ' ')
	for i := 0; i < len(rest)+1; i++ {
		g.echoNow(echo, 0x1b, '[', 'D')
	}
}

func (g *CommandGuard) deleteForward(echo *[]byte) {
	if g.cursor >= len(g.buf) {
		return
	}
	rest := append([]byte(nil), g.buf[g.cursor+1:]...)
	g.buf = append(g.buf[:g.cursor], rest...)
	if len(rest) == 0 {
		g.echoNow(echo, ' ', 0x08)
		return
	}
	g.echoNow(echo, rest...)
	g.echoNow(echo, ' ')
	for i := 0; i < len(rest)+1; i++ {
		g.echoNow(echo, 0x1b, '[', 'D')
	}
}

func (g *CommandGuard) moveLeft(echo *[]byte) {
	if g.cursor <= 0 {
		return
	}
	g.cursor--
	g.echoNow(echo, 0x1b, '[', 'D')
}

func (g *CommandGuard) moveRight(echo *[]byte) {
	if g.cursor >= len(g.buf) {
		return
	}
	g.cursor++
	g.echoNow(echo, 0x1b, '[', 'C')
}

func (g *CommandGuard) moveHome(echo *[]byte) {
	for g.cursor > 0 {
		g.cursor--
		g.echoNow(echo, 0x1b, '[', 'D')
	}
}

func (g *CommandGuard) moveEnd(echo *[]byte) {
	for g.cursor < len(g.buf) {
		g.cursor++
		g.echoNow(echo, 0x1b, '[', 'C')
	}
}

func (g *CommandGuard) clearLine(echo *[]byte) {
	g.moveEnd(echo)
	for g.cursor > 0 {
		g.backspace(echo)
	}
	g.buf = g.buf[:0]
	g.cursor = 0
}
