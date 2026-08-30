package dbproxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf16"
)

const (
	tnsConnect byte = 1
	tnsAccept  byte = 2
	tnsRefuse  byte = 4
	tnsData    byte = 6
	tnsNull    byte = 7
	tnsAbort   byte = 9
	tnsResend  byte = 11
	tnsMarker  byte = 12
)

const maxTNSPacket = 1024 * 1024

type tnsPacket struct {
	typ     byte
	payload []byte
}

func writeTNS(w io.Writer, typ byte, payload []byte) error {
	n := 8 + len(payload)
	if n > maxTNSPacket {
		return fmt.Errorf("tns packet too large")
	}
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(n))
	hdr[4] = typ
	_, err := w.Write(append(hdr, payload...))
	return err
}

func readTNS(r io.Reader) (tnsPacket, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return tnsPacket{}, err
	}
	typ := hdr[4]
	length := int(binary.BigEndian.Uint16(hdr[0:2]))
	if hdr[0] == 0 && hdr[1] == 0 {
		length = int(binary.BigEndian.Uint32(hdr[0:4]))
	}
	if length < 8 || length > maxTNSPacket {
		return tnsPacket{}, fmt.Errorf("bad tns length %d", length)
	}
	rest := make([]byte, length-8)
	if len(rest) > 0 {
		if _, err := io.ReadFull(r, rest); err != nil {
			return tnsPacket{}, err
		}
	}
	return tnsPacket{typ: typ, payload: rest}, nil
}

func tnsAcceptPayload() []byte {
	p := make([]byte, 24)
	binary.BigEndian.PutUint16(p[0:2], 313)
	binary.BigEndian.PutUint16(p[4:6], 8192)
	binary.BigEndian.PutUint16(p[6:8], 32767)
	binary.BigEndian.PutUint16(p[8:10], 1)
	binary.BigEndian.PutUint16(p[12:14], 32)
	p[14], p[15] = 1, 1
	return p
}

func tnsRefusePayload(msg string) []byte {
	p := make([]byte, 8)
	p = append(p, []byte(msg)...)
	return p
}

func connectDataFromPayload(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	if len(payload) >= 20 {
		dataLen := int(binary.BigEndian.Uint16(payload[16:18]))
		dataOff := int(binary.BigEndian.Uint16(payload[18:20]))
		start := dataOff - 8
		if start >= 0 && start <= len(payload) && dataLen >= 0 {
			end := start + dataLen
			if end > len(payload) {
				end = len(payload)
			}
			if end > start {
				s := string(payload[start:end])
				if strings.Contains(s, "(") {
					return s
				}
			}
		}
	}
	if i := strings.IndexByte(string(payload), '('); i >= 0 {
		return string(payload[i:])
	}
	return ""
}

func tnsNVP(s, key string) string {
	upper := strings.ToUpper(s)
	needle := "(" + strings.ToUpper(key) + "="
	for i := 0; i < len(upper); {
		j := strings.Index(upper[i:], needle)
		if j < 0 {
			return ""
		}
		j += i
		start := j + len(needle)
		depth := 1
		for k := start; k < len(s); k++ {
			switch s[k] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					return strings.TrimSpace(s[start:k])
				}
			}
		}
		i = j + 1
	}
	return ""
}

func tnsAllNVP(s, key string) []string {
	var out []string
	upper := strings.ToUpper(s)
	needle := "(" + strings.ToUpper(key) + "="
	for i := 0; i < len(upper); {
		j := strings.Index(upper[i:], needle)
		if j < 0 {
			break
		}
		j += i
		start := j + len(needle)
		depth := 1
		found := ""
		endAt := -1
		for k := start; k < len(s); k++ {
			switch s[k] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					found = strings.TrimSpace(s[start:k])
					endAt = k
					break
				}
			}
		}
		if found != "" {
			out = append(out, found)
		}
		if endAt > i {
			i = endAt + 1
		} else {
			i = j + 1
		}
	}
	return out
}

type oracleConnect struct {
	user, pass, service string
}

func parseOracleConnect(desc string) oracleConnect {
	var c oracleConnect
	c.user = strings.TrimSpace(tnsNVP(desc, "KEEPPAM_USER"))
	c.pass = tnsNVP(desc, "KEEPPAM_PASS")
	if c.pass == "" {
		c.pass = tnsNVP(desc, "PASSWORD")
	}
	c.service = strings.TrimSpace(tnsNVP(desc, "SERVICE_NAME"))
	if c.service == "" {
		c.service = strings.TrimSpace(tnsNVP(desc, "SID"))
	}
	if c.user == "" {
		for _, u := range tnsAllNVP(desc, "USER") {
			if pickOracleUser(u) != "" {
				c.user = pickOracleUser(u)
				break
			}
		}
	}
	if isHexToken(c.service) && c.pass == "" {
		c.pass = c.service
		c.service = ""
	}
	if looksLikeUUID(c.service) && c.user == "" {
		c.user = c.service
		c.service = ""
	}
	return c
}

func pickOracleUser(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if looksLikeUUID(s) || strings.Contains(s, "+") {
		return s
	}
	return ""
}

var (
	reUUID     = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	reHexToken = regexp.MustCompile(`(?i)\b[0-9a-f]{24,64}\b`)
	rePamUser  = regexp.MustCompile(`[A-Za-z0-9._-]+\+[A-Za-z0-9._/-]+`)
	reSQL      = regexp.MustCompile(`(?is)\b(SELECT|INSERT|UPDATE|DELETE|MERGE|WITH|BEGIN|CALL|DECLARE|EXPLAIN|TRUNCATE|CREATE|DROP|ALTER|GRANT|REVOKE|COMMIT|ROLLBACK)\b[\s\S]{0,1000}`)
)

func looksLikeUUID(s string) bool {
	return reUUID.MatchString(strings.TrimSpace(s)) && len(strings.TrimSpace(s)) >= 36
}

func isHexToken(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 24 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func extractOracleAuth(p []byte) (user, pass string) {
	texts := append([]string{string(p)}, utf16Strings(p)...)
	joined := strings.Join(texts, "\n")
	if m := reUUID.FindString(joined); m != "" {
		user = m
	}
	if user == "" {
		if m := rePamUser.FindString(joined); m != "" {
			user = m
		}
	}
	if m := reHexToken.FindString(joined); m != "" {
		pass = m
	}
	return user, pass
}

func utf16Strings(p []byte) []string {
	var out []string
	if len(p) < 4 {
		return out
	}
	u16 := make([]uint16, 0, len(p)/2)
	for i := 0; i+1 < len(p); i += 2 {
		u16 = append(u16, binary.LittleEndian.Uint16(p[i:i+2]))
	}
	s := string(utf16.Decode(u16))
	var b strings.Builder
	flush := func() {
		v := strings.TrimSpace(b.String())
		if len(v) >= 3 {
			out = append(out, v)
		}
		b.Reset()
	}
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func extractSQL(p []byte) string {
	s := strings.TrimSpace(strings.ReplaceAll(string(p), "\x00", " "))
	if m := reSQL.FindString(s); m != "" {
		return strings.TrimSpace(strings.TrimRight(m, " \t\r\n;"))
	}
	for _, t := range utf16Strings(p) {
		if m := reSQL.FindString(t); m != "" {
			return strings.TrimSpace(strings.TrimRight(m, " \t\r\n;"))
		}
	}
	return ""
}

func tnsDataFlags(payload []byte) (flags []byte, body []byte) {
	if len(payload) >= 2 {
		return payload[:2], payload[2:]
	}
	return nil, payload
}

func ttcKind(body []byte) byte {
	if len(body) == 0 {
		return 0
	}
	return body[0]
}

func tnsDataPayload(body []byte) []byte {
	out := []byte{0, 0}
	return append(out, body...)
}
