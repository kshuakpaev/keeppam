package tn3270

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// field attr unprotected + MDT-capable
const (
	attrUnprot = 0x40 // unprotected, alphanumeric
	attrProt   = 0x60 // protected
	attrHidden = 0x4C // unprotected nondisplay (password)
)

// LoginScreen sends a simple Erase/Write login form and reads AID+fields.
func LoginScreen(c net.Conn, banner string, cp Codepage) (user, pass string, err error) {
	if banner == "" {
		banner = "KeepPAM TN3270"
	}
	cp = NormalizeCodepage(string(cp))
	payload := buildLoginScreen(banner, cp)
	if _, err = c.Write(FrameEOR(payload)); err != nil {
		return "", "", err
	}
	_ = c.SetDeadline(time.Now().Add(120 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()

	buf := make([]byte, 8192)
	pending := []byte(nil)
	for {
		n, rerr := c.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
			frames, rest := SplitEOR(pending)
			pending = rest
			for _, fr := range frames {
				user, pass, ok := parseLoginResponse(fr, cp)
				if ok {
					return user, pass, nil
				}
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return "", "", fmt.Errorf("client closed during login")
			}
			return "", "", rerr
		}
	}
}

func buildLoginScreen(banner string, cp Codepage) []byte {
	// Erase/Write + WCC (reset MDT, keyboard restore)
	out := []byte{0xF5, 0xC3}
	out = append(out, putText(0, banner, cp)...)
	out = append(out, putText(80, "Session UUID:", cp)...)
	out = append(out, sba(81+14)...)
	out = append(out, 0x1D, attrUnprot)
	out = append(out, bytes.Repeat([]byte{0x00}, 40)...) // field room
	out = append(out, putText(160, "Wire token:", cp)...)
	out = append(out, sba(161+12)...)
	out = append(out, 0x1D, attrHidden)
	out = append(out, bytes.Repeat([]byte{0x00}, 48)...)
	out = append(out, putText(240, "Press Enter after filling fields.", cp)...)
	// IC to first field
	out = append(out, sba(81+14)...)
	out = append(out, 0x13) // Insert Cursor
	return out
}

func putText(pos int, s string, cp Codepage) []byte {
	var out []byte
	out = append(out, sba(pos)...)
	out = append(out, 0x1D, attrProt)
	out = append(out, EncodeString(s, cp)...)
	return out
}

func sba(pos int) []byte {
	if pos < 0 {
		pos = 0
	}
	if pos > 0xFFF {
		pos = 0xFFF
	}
	return []byte{0x11, byte(0x40 | ((pos >> 6) & 0x3F)), byte(0x40 | (pos & 0x3F))}
}

func parseLoginResponse(fr []byte, cp Codepage) (user, pass string, ok bool) {
	if len(fr) < 1 {
		return "", "", false
	}
	// AID: Enter=0x7D, others still try parse
	i := 1
	if len(fr) >= 3 {
		// cursor address often follows AID
		i = 3
	}
	var fields []string
	for i < len(fr) {
		if fr[i] == 0x11 && i+2 < len(fr) { // SBA
			i += 3
			start := i
			for i < len(fr) && fr[i] != 0x11 && fr[i] != 0x1D {
				i++
			}
			fields = append(fields, strings.TrimSpace(DecodeBytes(fr[start:i], cp)))
			continue
		}
		i++
	}
	if len(fields) >= 2 {
		return fields[0], fields[1], fields[0] != "" && fields[1] != ""
	}
	if len(fields) == 1 && strings.Contains(fields[0], " ") {
		parts := strings.Fields(fields[0])
		if len(parts) >= 2 {
			return parts[0], parts[1], true
		}
	}
	return "", "", false
}
