package tn3270

import "strings"

// Codepage is an EBCDIC encoding used for TN3270 forensic decode.
type Codepage string

const (
	CP037 Codepage = "cp037" // US Latin (default)
	CP930 Codepage = "cp930" // Japanese Katakana/Kanji
	CP939 Codepage = "cp939" // Japanese Latin/Kanji
	CP933 Codepage = "cp933" // Korean Hangul
)

// NormalizeCodepage returns a supported codepage id.
func NormalizeCodepage(s string) Codepage {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "cp930", "930":
		return CP930
	case "cp939", "939":
		return CP939
	case "cp933", "933":
		return CP933
	default:
		return CP037
	}
}

// DefaultTermType picks a TERMINAL-TYPE for negotiate when asset override is empty.
func DefaultTermType(cp Codepage) string {
	switch cp {
	case CP930, CP939:
		return "IBM-3279-4"
	case CP933:
		return "IBM-3278-5"
	default:
		return "IBM-3278-2"
	}
}

// NormalizeTermType validates TERMINAL-TYPE or returns empty for auto.
func NormalizeTermType(s string) string {
	switch strings.TrimSpace(s) {
	case "IBM-3278-2", "IBM-3278-4", "IBM-3279-4", "IBM-3278-5":
		return strings.TrimSpace(s)
	default:
		return ""
	}
}

// ResolveTermType returns asset override or codepage default.
func ResolveTermType(termType string, cp Codepage) string {
	if t := NormalizeTermType(termType); t != "" {
		return t
	}
	return DefaultTermType(cp)
}

// IsDBCSCodepage reports whether double-byte EBCDIC pairs are expected.
func IsDBCSCodepage(cp Codepage) bool {
	switch cp {
	case CP930, CP939, CP933:
		return true
	default:
		return false
	}
}

// IsDBCSLead byte in IBM mixed SBCS/DBCS codepages.
func IsDBCSLead(b byte) bool {
	if b < 0x41 || b == 0xFF {
		return false
	}
	switch b {
	case 0x40, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F:
		return false
	}
	return true
}
