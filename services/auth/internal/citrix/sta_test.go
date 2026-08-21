package citrix

import (
	"strings"
	"testing"
)

func TestBuildICAFile_STAAndStoreFront(t *testing.T) {
	s := BuildICAFile(ICAFileOpts{
		ProxyHost: "pam.example.com", ProxyPort: 1081,
		ProxyUser: "11111111-1111-1111-1111-111111111111", ProxyPassword: "tok",
		TargetHost: "vda.corp.local", TargetPort: 1494,
		AppName: "Finance", InitialProg: "#Excel", Title: "Finance",
		STATicket: "AABBCCDDEEFF00112233445566778899", StoreFrontURL: "https://sf.corp/Citrix/Store",
		Username: "ops",
	})
	for _, want := range []string{
		"STATicket=AABBCCDDEEFF00112233445566778899",
		"KeepPAMSTATicket=AABBCCDDEEFF00112233445566778899",
		"LocHttpBrowserAddress=https://sf.corp/Citrix/Store",
		"InitialProgram=#Excel",
		"Username=ops",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}
