package tn3270

// Minimal EBCDIC CP037 (US) ↔ Unicode for Latin letters, digits, space, common punct.
// Enough for login screens and forensic text extraction.

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

// DecodeEBCDIC maps CP037 bytes to UTF-8 (skips unmapped/controls).
func DecodeEBCDIC(in []byte) string {
	out := make([]rune, 0, len(in))
	for _, b := range in {
		r := e2u[b]
		if r == 0xFFFD {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// EncodeEBCDIC maps UTF-8 to CP037 (unknown → space).
func EncodeEBCDIC(s string) []byte {
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
