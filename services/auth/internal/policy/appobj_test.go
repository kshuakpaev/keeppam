package policy

import "testing"

func TestMatchAppObjectCRM(t *testing.T) {
	pack := AppObjectPack{
		Name:      "crm-objects",
		Unmatched: "deny",
		Rules: []string{
			"GET /api/customers/export customer.export approval",
			"GET /api/customers* customer.view allow",
			"POST /api/customers customer.create allow",
			"PUT /api/customers/* customer.update allow",
			"PATCH /api/customers/* customer.update allow",
			"DELETE /api/customers/* customer.delete deny",
			"* /admin* admin.panel deny",
		},
	}
	cases := []struct {
		method, path, object, action string
		allowed, matched             bool
		code                         string
	}{
		{"GET", "/api/customers/1", "customer.view", "allow", true, true, ""},
		{"GET", "/api/customers/export", "customer.export", "approval", false, true, "approval_required"},
		{"POST", "/api/customers", "customer.create", "allow", true, true, ""},
		{"PUT", "/api/customers/9", "customer.update", "allow", true, true, ""},
		{"DELETE", "/api/customers/9", "customer.delete", "deny", false, true, "app_denied"},
		{"GET", "/admin/users", "admin.panel", "deny", false, true, "app_denied"},
		{"GET", "/health", "", "deny", false, false, "app_denied"},
	}
	for _, c := range cases {
		d := MatchAppObject(pack, c.method, c.path)
		if d.Allowed != c.allowed || d.Matched != c.matched || d.Object != c.object || d.Action != c.action || d.Code != c.code {
			t.Errorf("%s %s: %+v want allowed=%v matched=%v obj=%s action=%s code=%s",
				c.method, c.path, d, c.allowed, c.matched, c.object, c.action, c.code)
		}
	}
}

func TestMatchAppObjectUnmatchedAllow(t *testing.T) {
	pack := AppObjectPack{
		Unmatched: "allow",
		Rules:     []string{"DELETE /api/customers/* customer.delete deny"},
	}
	d := MatchAppObject(pack, "GET", "/other")
	if !d.Allowed || d.Matched {
		t.Fatalf("unmatched allow: %+v", d)
	}
	d = MatchAppObject(pack, "DELETE", "/api/customers/1")
	if d.Allowed || d.Object != "customer.delete" {
		t.Fatalf("delete: %+v", d)
	}
}

func TestParseAppObjectRule(t *testing.T) {
	if _, ok := parseAppObjectRule("GET /x bad"); ok {
		t.Fatal("expected reject 3 fields")
	}
	if _, ok := parseAppObjectRule("GET /x 1customer.view allow"); ok {
		t.Fatal("expected reject object starting with digit")
	}
	r, ok := parseAppObjectRule("get /Api/x Customer.View ALLOW")
	if !ok || r.Method != "GET" || r.Path != "/Api/x" || r.Object != "customer.view" || r.Action != "allow" {
		t.Fatalf("got %+v ok=%v", r, ok)
	}
}
