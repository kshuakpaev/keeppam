package rdpgw

import (
	"strings"
	"testing"

	"github.com/keeppam/auth/internal/policy"
)

func TestBuildRDPFileDLPStrict(t *testing.T) {
	s := BuildRDPFile("pam.local", 3390, "sess-uuid", policy.RDPRedir{}, 0, 0)
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
	s := BuildRDPFile("pam.local", 0, "u", policy.RDPRedir{Clipboard: true, Drive: true, Printer: true}, 0, 0)
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

func TestBuildRDPFileRemoteApp(t *testing.T) {
	s := BuildRDPFile("pam.local", 3390, "u", policy.RDPRedir{}, 1920, 1080, RemoteAppOpts{Program: "||Notepad", Dir: `C:\Windows`})
	for _, want := range []string{
		"remoteapplicationmode:i:1",
		"remoteapplicationprogram:s:||Notepad",
		`remoteapplicationdir:s:C:\Windows`,
		"desktopwidth:i:1920",
		"desktopheight:i:1080",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}
