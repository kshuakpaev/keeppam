package citrix

import (
	"strings"
	"testing"
)

func TestBuildICAFile(t *testing.T) {
	s := BuildICAFile(ICAFileOpts{
		ProxyHost: "pam.example.com", ProxyPort: 1081,
		ProxyUser: "11111111-1111-1111-1111-111111111111", ProxyPassword: "tok",
		TargetHost: "vda.corp.local", TargetPort: 1494,
		AppName: "Finance", InitialProg: "#Excel", Title: "Finance",
	})
	for _, want := range []string{
		"ProxyType=Socks",
		"ProxyHost=pam.example.com",
		"ProxyPort=1081",
		"Address=vda.corp.local",
		"CGPAddress=*:2598",
		"InitialProgram=#Excel",
		"[Finance]",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}

func TestSanitizeSection(t *testing.T) {
	if sanitizeSection("A B!") != "AB" {
		t.Fatal(sanitizeSection("A B!"))
	}
}
