package castindex

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/keeppam/auth/internal/policy"
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

func TestOCRStoreCap(t *testing.T) {
	if ocrStoreCap(0) != policy.OCRDefaultFrames {
		t.Fatal("default")
	}
	if ocrStoreCap(999) != policy.OCRMaxFramesCap {
		t.Fatal("cap")
	}
}
