package tn3270

import (
	"fmt"
	"io"
	"net"
	"time"
)

const (
	iac  = 255
	dont = 254
	doOpt = 253
	wont = 252
	will = 251
	sb   = 250
	se   = 240
	eor  = 239

	optBinary = 0
	optSGA    = 3
	optTType  = 24
	optEOR    = 25
)

// NegotiateServer performs TN3270 options toward a client (we are the server).
func NegotiateServer(c net.Conn, termType string) error {
	if termType == "" {
		termType = "IBM-3278-2"
	}
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()

	init := concat(
		cmd(doOpt, optBinary), cmd(will, optBinary),
		cmd(doOpt, optEOR), cmd(will, optEOR),
		cmd(doOpt, optSGA), cmd(will, optSGA),
		cmd(doOpt, optTType),
	)
	if _, err := c.Write(init); err != nil {
		return err
	}
	return drainNegotiate(c, termType, true)
}

// NegotiateClient performs TN3270 options toward a host (we are the client).
func NegotiateClient(c net.Conn, termType string) error {
	if termType == "" {
		termType = "IBM-3278-2"
	}
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()

	init := concat(
		cmd(will, optBinary), cmd(doOpt, optBinary),
		cmd(will, optEOR), cmd(doOpt, optEOR),
		cmd(will, optSGA), cmd(doOpt, optSGA),
		cmd(will, optTType),
	)
	if _, err := c.Write(init); err != nil {
		return err
	}
	return drainNegotiate(c, termType, false)
}

func drainNegotiate(c net.Conn, termType string, asServer bool) error {
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 4096)
	pending := []byte(nil)
	gotTType := false
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := c.Read(buf)
		if n > 0 {
			app, rest, replies := handleIAC(append(pending, buf[:n]...), termType, asServer)
			pending = rest
			_ = app
			if len(replies) > 0 {
				if _, werr := c.Write(replies); werr != nil {
					return werr
				}
				if containsTTypeIS(replies) {
					gotTType = true
				}
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if gotTType || time.Now().After(deadline.Add(-500*time.Millisecond)) {
					return nil
				}
				continue
			}
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
	return nil
}

func handleIAC(in []byte, termType string, asServer bool) (app, rest, replies []byte) {
	i := 0
	for i < len(in) {
		if in[i] != iac {
			app = append(app, in[i])
			i++
			continue
		}
		if i+1 >= len(in) {
			return app, in[i:], replies
		}
		cmdb := in[i+1]
		switch cmdb {
		case iac:
			app = append(app, iac)
			i += 2
		case will, wont, doOpt, dont:
			if i+2 >= len(in) {
				return app, in[i:], replies
			}
			opt := in[i+2]
			replies = append(replies, replyOpt(cmdb, opt, asServer)...)
			i += 3
		case sb:
			j := i + 2
			for j+1 < len(in) {
				if in[j] == iac && in[j+1] == se {
					if i+2 < j && in[i+2] == optTType {
						replies = append(replies, ttypeReply(in[i+3:j], termType, asServer)...)
					}
					i = j + 2
					break
				}
				j++
			}
			if j+1 >= len(in) {
				return app, in[i:], replies
			}
		case eor:
			i += 2 // EOR during negotiate — ignore
		default:
			i += 2
		}
	}
	return app, nil, replies
}

func replyOpt(cmdb, opt byte, asServer bool) []byte {
	switch cmdb {
	case will:
		switch opt {
		case optBinary, optEOR, optSGA, optTType:
			return cmd(doOpt, opt)
		default:
			return cmd(dont, opt)
		}
	case doOpt:
		switch opt {
		case optBinary, optEOR, optSGA, optTType:
			return cmd(will, opt)
		default:
			return cmd(wont, opt)
		}
	case wont, dont:
		return nil
	}
	_ = asServer
	return nil
}

func ttypeReply(data []byte, termType string, asServer bool) []byte {
	// SB TERMINAL-TYPE SEND (1) → respond IS (0) name
	if len(data) >= 1 && data[0] == 1 {
		b := []byte{iac, sb, optTType, 0}
		b = append(b, termType...)
		b = append(b, iac, se)
		return b
	}
	return nil
}

func containsTTypeIS(b []byte) bool {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == iac && b[i+1] == sb && b[i+2] == optTType && b[i+3] == 0 {
			return true
		}
	}
	return false
}

func cmd(c, opt byte) []byte { return []byte{iac, c, opt} }

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// FrameEOR wraps a 3270 data stream payload with IAC EOR.
func FrameEOR(payload []byte) []byte {
	out := make([]byte, 0, len(payload)*2+2)
	for _, b := range payload {
		out = append(out, b)
		if b == iac {
			out = append(out, iac) // escape
		}
	}
	return append(out, iac, eor)
}

// SplitEOR extracts complete 3270 payloads; returns remainder.
func SplitEOR(buf []byte) (frames [][]byte, rest []byte) {
	start := 0
	i := 0
	for i < len(buf) {
		if buf[i] == iac {
			if i+1 >= len(buf) {
				return frames, buf[start:]
			}
			if buf[i+1] == iac {
				i += 2
				continue
			}
			if buf[i+1] == eor {
				raw := buf[start:i]
				frames = append(frames, unescapeIAC(raw))
				i += 2
				start = i
				continue
			}
		}
		i++
	}
	return frames, buf[start:]
}

func unescapeIAC(in []byte) []byte {
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		if in[i] == iac && i+1 < len(in) && in[i+1] == iac {
			out = append(out, iac)
			i++
			continue
		}
		out = append(out, in[i])
	}
	return out
}

// ExtractScreenText best-effort pulls printable EBCDIC from a 3270 data stream.
func ExtractScreenText(stream []byte) string {
	if len(stream) == 0 {
		return ""
	}
	// Skip leading command / WCC when present
	i := 0
	if stream[0] == 0xF1 || stream[0] == 0xF5 || stream[0] == 0x7E || stream[0] == 0xF2 {
		i = 1
		if i < len(stream) {
			i++ // WCC
		}
	}
	var eb []byte
	for i < len(stream) {
		b := stream[i]
		switch b {
		case 0x11: // SBA
			i += 3
		case 0x1D: // SF
			i += 2
		case 0x28: // SA
			i += 3
		case 0x13: // IC
			i++
		case 0x05: // PT
			i++
		case 0x3C: // RA
			i += 4
		case 0x12: // EUA
			i += 3
		case 0x08: // GE
			i += 2
		default:
			if b >= 0x40 || b == 0x00 {
				eb = append(eb, b)
			}
			i++
		}
	}
	s := DecodeEBCDIC(eb)
	if len(s) > 4000 {
		s = s[:4000]
	}
	return s
}

// Dial opens TCP to host:port (default 23).
func Dial(host string, port int) (net.Conn, error) {
	if port <= 0 {
		port = 23
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	return d.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
}
