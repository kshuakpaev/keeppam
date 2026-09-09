package sshgw

import (
	"strings"
	"testing"
)

func TestParseSSHPort(t *testing.T) {
	if got := ParseSSHPort(":2222"); got != 2222 {
		t.Fatalf("got %d", got)
	}
	if got := ParseSSHPort("0.0.0.0:2223"); got != 2223 {
		t.Fatalf("got %d", got)
	}
	if got := ParseSSHPort(""); got != 2222 {
		t.Fatalf("default %d", got)
	}
}

func TestBuildPuTTYLauncherCMD(t *testing.T) {
	body := BuildPuTTYLauncherCMD(ConnFileOpts{
		PublicHost:  "pam.example.com",
		Port:        2222,
		PAMUser:     "ops",
		AssetName:   "demo-linux-01",
		AccountName: "root",
	})
	for _, want := range []string{
		"putty.exe",
		"-ssh",
		"%KP_USER%@%KP_HOST%",
		"-P %KP_PORT%",
		"-m",
		"demo-linux-01/root",
		`ProgramFiles%\PuTTY\putty.exe`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "-pw") {
		t.Fatal("expected no -pw without wire token")
	}
}

func TestBuildPuTTYLauncherCMDWire(t *testing.T) {
	body := BuildPuTTYLauncherCMD(ConnFileOpts{
		PublicHost:  "10.0.0.5",
		Port:        2222,
		PAMUser:     "ops",
		AssetName:   "demo-linux-01",
		AccountName: "root",
		WireUser:    "11111111-2222-3333-4444-555555555555",
		WirePass:    "abcd1234deadbeef",
	})
	for _, want := range []string{
		"set \"KP_USER=11111111-2222-3333-4444-555555555555\"",
		"set \"KP_PASS=abcd1234deadbeef\"",
		"-pw %KP_PASS%",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
}

func TestBuildSSHConfigFile(t *testing.T) {
	body := BuildSSHConfigFile(ConnFileOpts{
		PublicHost:   "pam.example.com",
		Port:         2222,
		PAMUser:      "ops",
		AssetName:    "demo-linux-01",
		AccountName:  "root",
		IncludePutty: true,
	})
	for _, want := range []string{
		"Host keeppam-demo-linux-01-root",
		"HostName pam.example.com",
		"Port 2222",
		"User ops",
		"RemoteCommand demo-linux-01/root",
		"PuTTY",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
	hint := BuildSSHHint(ConnFileOpts{
		PublicHost: "pam.example.com", Port: 2222, PAMUser: "ops",
		AssetName: "demo-linux-01", AccountName: "root",
	})
	if !strings.Contains(hint, "ops@pam.example.com") || !strings.Contains(hint, "demo-linux-01/root") {
		t.Fatalf("hint %q", hint)
	}
}
