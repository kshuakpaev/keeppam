package firewall

import "testing"

func TestPamOnlyForwardBlocked(t *testing.T) {
	targets := []Target{{
		Name: "web", Address: "10.1.2.5", Hostname: "web.prod", Port: 22, Protocol: "ssh", PamOnly: true,
	}}
	if r, ok := PamOnlyForwardBlocked("10.1.2.5", 22, targets); !ok {
		t.Fatal("expected block")
	} else if r == "" {
		t.Fatal("reason")
	}
	if _, ok := PamOnlyForwardBlocked("web.prod", 22, targets); !ok {
		t.Fatal("hostname")
	}
	if _, ok := PamOnlyForwardBlocked("10.1.2.5", 5432, []Target{{
		Name: "db", Address: "10.1.2.5", Port: 5432, Protocol: "postgres", PamOnly: true,
	}}); !ok {
		t.Fatal("postgres forward")
	}
	targets[0].PamOnly = false
	if _, ok := PamOnlyForwardBlocked("10.1.2.5", 22, targets); ok {
		t.Fatal("pam_only off")
	}
}

func TestValidateGatewayCIDRs(t *testing.T) {
	out, err := ValidateGatewayCIDRs([]string{"10.0.0.0/8", "10.0.0.0/8", "bad"})
	if err == nil {
		t.Fatal("bad cidr")
	}
	out, err = ValidateGatewayCIDRs([]string{"10.0.1.0/24", "10.0.2.0/24"})
	if err != nil || len(out) != 2 {
		t.Fatalf("%v %v", out, err)
	}
}
