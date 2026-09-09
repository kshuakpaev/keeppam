package rdpgw

import (
	"strings"
	"testing"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/policy"
)

func TestBuildDirectRDPFile(t *testing.T) {
	s := BuildDirectRDPFile("10.1.2.3", 3389, "Administrator", policy.RDPRedir{}, 0, 0, false)
	for _, want := range []string{
		"full address:s:10.1.2.3:3389\r\n",
		"username:s:Administrator\r\n",
		"prompt for credentials:i:0\r\n",
		"enablecredsspsupport:i:1\r\n",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%q", want, s)
		}
	}
	if strings.Contains(s, "password:") {
		t.Fatalf("mstsc-safe .rdp must not contain password fields:\n%s", s)
	}
}

func TestBuildDirectRDPFilePrompt(t *testing.T) {
	s := BuildDirectRDPFile("10.1.2.3", 3389, "Administrator", policy.RDPRedir{}, 0, 0, true)
	if !strings.Contains(s, "prompt for credentials:i:1\r\n") {
		t.Fatalf("expected prompt:\n%s", s)
	}
}

func TestBuildRDPCredLauncherCMD(t *testing.T) {
	s := BuildRDPCredLauncherCMD("keeppam-abcd.rdp", "10.1.2.3", `dom\adm`, `p'ass`)
	for _, want := range []string{
		"cmdkey /generic:'TERMSRV/10.1.2.3'",
		`/user:'dom\adm'`,
		"/pass:'p''ass'",
		"mstsc",
		"cmdkey /delete:'TERMSRV/10.1.2.3'",
		"keeppam-abcd.rdp",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}

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

func TestBuildProxyINISessionCapture(t *testing.T) {
	creds := assets.TargetCreds{}
	creds.Asset.Address = "10.0.0.8"
	creds.Asset.Port = 3389
	creds.Account.Username = "adm"
	creds.Secret = "x"
	ini := buildProxyINI(3390, creds, policy.RDPRedir{}, "", "", "/rec/rdp-native/abc")
	for _, want := range []string{
		"[SessionCapture]",
		"Enabled = TRUE",
		`CapturesDirectory = "/rec/rdp-native/abc"`,
	} {
		if !strings.Contains(ini, want) {
			t.Fatalf("missing %q in:\n%s", want, ini)
		}
	}
}
