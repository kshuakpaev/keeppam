package sshkrb

import "testing"

func TestSPN(t *testing.T) {
	if got := SPN("host/%h", "srv.corp.local"); got != "host/srv.corp.local" {
		t.Fatalf("%q", got)
	}
	if got := HostLabel("srv.corp.local", "10.0.0.1"); got != "srv.corp.local" {
		t.Fatalf("%q", got)
	}
	if got := HostLabel("srv", "10.0.0.1"); got != "10.0.0.1" {
		t.Fatalf("%q", got)
	}
}

func TestSplitPrincipal(t *testing.T) {
	u, r := splitPrincipal("user@CORP.LOCAL", "OTHER")
	if u != "user" || r != "CORP.LOCAL" {
		t.Fatalf("%s %s", u, r)
	}
}
