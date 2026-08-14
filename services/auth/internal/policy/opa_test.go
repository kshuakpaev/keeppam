package policy

import (
	"context"
	"strings"
	"testing"
)

func TestLoadOPADisabled(t *testing.T) {
	e, err := LoadOPA("")
	if err != nil || e != nil {
		t.Fatalf("empty path: eng=%v err=%v", e, err)
	}
}

func TestCompileOPASetDeny(t *testing.T) {
	src := `package keeppam.authz

deny[msg] {
  input.asset.protocol == "kubectl"
  input.request.ticket_id == ""
  msg := "kubectl requires ticket_id"
}
`
	e, err := CompileOPA(src)
	if err != nil {
		t.Fatal(err)
	}
	if e.Package() != "keeppam.authz" {
		t.Fatalf("pkg=%s", e.Package())
	}
	denied, reason, err := e.Deny(context.Background(), map[string]any{
		"asset":   map[string]any{"protocol": "kubectl"},
		"request": map[string]any{"ticket_id": ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !denied || !strings.Contains(reason, "ticket_id") {
		t.Fatalf("denied=%v reason=%q", denied, reason)
	}
	denied, _, err = e.Deny(context.Background(), map[string]any{
		"asset":   map[string]any{"protocol": "kubectl"},
		"request": map[string]any{"ticket_id": "INC-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if denied {
		t.Fatal("expected allow with ticket")
	}
}

func TestCompileOPABoolDeny(t *testing.T) {
	src := `package keeppam.authz

default deny = false

deny {
  input.user.username == "blocked"
}
`
	e, err := CompileOPA(src)
	if err != nil {
		t.Fatal(err)
	}
	denied, _, err := e.Deny(context.Background(), map[string]any{
		"user": map[string]any{"username": "blocked"},
	})
	if err != nil || !denied {
		t.Fatalf("denied=%v err=%v", denied, err)
	}
	denied, _, err = e.Deny(context.Background(), map[string]any{
		"user": map[string]any{"username": "ok"},
	})
	if err != nil || denied {
		t.Fatalf("allow failed denied=%v err=%v", denied, err)
	}
}

func TestCompileOPANoopAllow(t *testing.T) {
	src := `package keeppam.authz
# extra deny rules go here
`
	e, err := CompileOPA(src)
	if err != nil {
		t.Fatal(err)
	}
	denied, _, err := e.Deny(context.Background(), map[string]any{"asset": map[string]any{"protocol": "ssh"}})
	if err != nil || denied {
		t.Fatalf("noop should allow denied=%v err=%v", denied, err)
	}
}

func TestCompileOPAInvalid(t *testing.T) {
	if _, err := CompileOPA("this is not rego"); err == nil {
		t.Fatal("expected compile error")
	}
}

func TestDenyMessageOPA(t *testing.T) {
	r := AccessResult{DeniedByOPA: true, OPAReason: "kubectl requires ticket_id"}
	msg := r.DenyMessage()
	if !strings.Contains(msg, "opa") || !strings.Contains(msg, "ticket_id") {
		t.Fatalf("msg=%s", msg)
	}
	p := map[string]any{"reason": "policy"}
	r.FillDenyPayload(p)
	if p["reason"] != "opa" || p["opa_reason"] != "kubectl requires ticket_id" {
		t.Fatalf("payload=%v", p)
	}
}
