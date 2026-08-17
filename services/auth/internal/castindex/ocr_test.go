package castindex

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCleanOCRLine(t *testing.T) {
	long := strings.Repeat("a", 600)
	got := cleanOCRLine(long)
	if utf8.RuneCountInString(got) != ocrMaxLine {
		t.Fatalf("len=%d", utf8.RuneCountInString(got))
	}
	if cleanOCRLine("  hi  ") != "hi" {
		t.Fatal()
	}
}
