package rdpgw

import (
	"strings"
	"testing"

	"github.com/keeppam/auth/internal/policy"
)

func TestBuildRDPFileDLPStrict(t *testing.T) {
	s := BuildRDPFile("pam.local", 3390, "sess-uuid", policy.RDPRedir{})
	for _, want := range []string{
		"full address:s:pam.local:3390",
		"redirectclipboard:i:0",
		"enablecredsspsupport:i:0",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}

func TestBuildRDPFileFull(t *testing.T) {
	s := BuildRDPFile("pam.local", 0, "u", policy.RDPRedir{Clipboard: true, Drive: true, Printer: true})
	for _, want := range []string{
		"full address:s:pam.local",
		"redirectclipboard:i:1",
		"redirectprinters:i:1",
		"drivestoredirect:s:*",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}
