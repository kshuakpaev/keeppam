package termcharset

import (
	"bytes"
	"encoding/base64"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
)

const (
	UTF8   = "utf-8"
	CP1251 = "cp1251"
	KOI8R  = "koi8-r"
	Auto   = "auto"
)

// Normalize returns a canonical charset id (default utf-8).
func Normalize(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", UTF8, "utf8", "ascii":
		return UTF8
	case CP1251, "windows-1251", "win1251", "1251":
		return CP1251
	case KOI8R, "koi8", "koi8r":
		return KOI8R
	case Auto:
		return Auto
	default:
		return UTF8
	}
}

// Result is UTF-8 text plus provenance for session_events payload.
type Result struct {
	Text    string
	Charset string
	RawB64  string // original bytes when re-encoded
}

// Decode converts terminal bytes to UTF-8 for recording / search index.
func Decode(raw []byte, charset string) Result {
	if len(raw) == 0 {
		return Result{Text: "", Charset: Normalize(charset)}
	}
	cs := Normalize(charset)
	rawB64 := base64.StdEncoding.EncodeToString(raw)

	if utf8.Valid(raw) && (cs == UTF8 || cs == Auto || looksUTF8Cyrillic(raw)) {
		return Result{Text: string(raw), Charset: UTF8}
	}

	switch cs {
	case CP1251:
		return Result{Text: mustDecode(charmap.Windows1251, raw), Charset: CP1251, RawB64: rawB64}
	case KOI8R:
		return Result{Text: mustDecode(charmap.KOI8R, raw), Charset: KOI8R, RawB64: rawB64}
	case Auto:
		best, used := detect(raw)
		return Result{Text: best, Charset: used, RawB64: rawB64}
	default:
		if utf8.Valid(raw) {
			return Result{Text: string(raw), Charset: UTF8}
		}
		best, used := detect(raw)
		return Result{Text: best, Charset: used, RawB64: rawB64}
	}
}

// DecodeString re-interprets a Go string as bytes (asciicast / JEA buffer).
func DecodeString(s, charset string) Result {
	return Decode([]byte(s), charset)
}

func mustDecode(enc encoding.Encoding, raw []byte) string {
	out, err := enc.NewDecoder().Bytes(raw)
	if err != nil || !utf8.Valid(out) {
		dec := enc.NewDecoder()
		var b bytes.Buffer
		_, _ = b.ReadFrom(dec.Reader(bytes.NewReader(raw)))
		if b.Len() > 0 {
			return b.String()
		}
		return string(raw)
	}
	return string(out)
}

func detect(raw []byte) (string, string) {
	cp := mustDecode(charmap.Windows1251, raw)
	ko := mustDecode(charmap.KOI8R, raw)
	scCP, scKO := scoreCyrillic(cp), scoreCyrillic(ko)
	if scKO > scCP {
		return ko, KOI8R
	}
	if scCP > 0 {
		return cp, CP1251
	}
	if utf8.Valid(raw) {
		return string(raw), UTF8
	}
	return cp, CP1251
}

func looksUTF8Cyrillic(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	return scoreCyrillic(string(raw)) > 0
}

func scoreCyrillic(s string) int {
	n := 0
	for _, r := range s {
		switch {
		case r >= 'а' && r <= 'я', r == 'ё':
			n += 3
		case r >= 'А' && r <= 'Я', r == 'Ё':
			n += 1
		case r >= 0x0400 && r <= 0x04FF:
			n += 1
		}
	}
	return n
}
