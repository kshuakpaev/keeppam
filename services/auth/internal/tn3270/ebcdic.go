package tn3270

// Minimal EBCDIC CP037 (US) ↔ Unicode for Latin letters, digits, space, common punct.
// DBCS codepages reuse CP037 SBCS layer + pair tables in codepage_dbcs.go.

var e2u [256]rune
var u2e = map[rune]byte{}

func init() {
	for i := range e2u {
		e2u[i] = 0xFFFD
	}
	set(' ', 0x40)
	for i, c := 0, 'a'; c <= 'i'; i, c = i+1, c+1 {
		set(c, byte(0x81+i))
	}
	for i, c := 0, 'j'; c <= 'r'; i, c = i+1, c+1 {
		set(c, byte(0x91+i))
	}
	for i, c := 0, 's'; c <= 'z'; i, c = i+1, c+1 {
		set(c, byte(0xA2+i))
	}
	for i, c := 0, 'A'; c <= 'I'; i, c = i+1, c+1 {
		set(c, byte(0xC1+i))
	}
	for i, c := 0, 'J'; c <= 'R'; i, c = i+1, c+1 {
		set(c, byte(0xD1+i))
	}
	for i, c := 0, 'S'; c <= 'Z'; i, c = i+1, c+1 {
		set(c, byte(0xE2+i))
	}
	for i, c := 0, '0'; c <= '9'; i, c = i+1, c+1 {
		set(c, byte(0xF0+i))
	}
	for r, b := range map[rune]byte{
		'.': 0x4B, '<': 0x4C, '(': 0x4D, '+': 0x4E, '|': 0x4F,
		'&': 0x50, '!': 0x5A, '$': 0x5B, '*': 0x5C, ')': 0x5D, ';': 0x5E, '^': 0x5F,
		'-': 0x60, '/': 0x61, ',': 0x6B, '%': 0x6C, '_': 0x6D, '>': 0x6E, '?': 0x6F,
		'`': 0x79, ':': 0x7A, '#': 0x7B, '@': 0x7C, '\'': 0x7D, '=': 0x7E, '"': 0x7F,
		'~': 0xA1, '[': 0xAD, ']': 0xBD, '{': 0xC0, '}': 0xD0, '\\': 0xE0,
	} {
		set(r, b)
	}
}

func set(r rune, b byte) {
	e2u[b] = r
	u2e[r] = b
}

func decodeSBCS(b byte) rune {
	r := e2u[b]
	if r == 0xFFFD {
		return 0
	}
	return r
}

// DecodeEBCDIC maps CP037 bytes to UTF-8 (skips unmapped/controls).
func DecodeEBCDIC(in []byte) string {
	return DecodeBytes(in, CP037)
}

// EncodeEBCDIC maps UTF-8 to CP037 (unknown → space).
func EncodeEBCDIC(s string) []byte {
	return EncodeString(s, CP037)
}

// DecodeBytes decodes EBCDIC bytes with optional DBCS pairs when cp is DBCS.
func DecodeBytes(in []byte, cp Codepage) string {
	if len(in) == 0 {
		return ""
	}
	dec := NewTextDecoder(cp)
	for i := 0; i < len(in); i++ {
		b := in[i]
		switch b {
		case 0x0E:
			dec.dbcs = true
		case 0x0F:
			dec.dbcs = false
		default:
			if dec.dbcs && IsDBCSCodepage(cp) && IsDBCSLead(b) && i+1 < len(in) {
				dec.WriteRune(decodeDBCSPair(cp, b, in[i+1]))
				i++
			} else if b >= 0x40 || b == 0x00 {
				if r := decodeSBCS(b); r != 0 {
					dec.WriteRune(r)
				}
			}
		}
	}
	return dec.String()
}

// EncodeString encodes UTF-8 to EBCDIC SBCS (DBCS runes → space unless in reverse map).
func EncodeString(s string, cp Codepage) []byte {
	_ = cp
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if b, ok := u2e[r]; ok {
			out = append(out, b)
		} else {
			out = append(out, 0x40)
		}
	}
	return out
}

// TextDecoder accumulates runes during stream parse.
type TextDecoder struct {
	cp   Codepage
	dbcs bool
	buf  []rune
}

func NewTextDecoder(cp Codepage) *TextDecoder {
	d := &TextDecoder{cp: NormalizeCodepage(string(cp))}
	if IsDBCSCodepage(d.cp) {
		d.dbcs = true
	}
	return d
}

func (d *TextDecoder) SetDBCS(on bool) { d.dbcs = on }

func (d *TextDecoder) DBCS() bool { return d.dbcs }

func (d *TextDecoder) WriteSBCS(b byte) {
	if r := decodeSBCS(b); r != 0 {
		d.buf = append(d.buf, r)
	}
}

func (d *TextDecoder) WriteDBCS(lead, trail byte) {
	if IsDBCSCodepage(d.cp) {
		d.buf = append(d.buf, decodeDBCSPair(d.cp, lead, trail))
	} else {
		d.WriteSBCS(lead)
	}
}

func (d *TextDecoder) WriteRune(r rune) {
	if r != 0 {
		d.buf = append(d.buf, r)
	}
}

func (d *TextDecoder) String() string {
	if len(d.buf) == 0 {
		return ""
	}
	return string(d.buf)
}
