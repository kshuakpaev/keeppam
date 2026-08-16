package policy

import "testing"

func TestMatchHTTPAllowlist(t *testing.T) {
	pack := HTTPPack{Mode: "allowlist", Rules: []string{"GET *", "HEAD *", "OPTIONS *"}}
	if ok, _ := MatchHTTP(pack, "GET", "/admin"); !ok {
		t.Fatal("GET /admin")
	}
	if ok, _ := MatchHTTP(pack, "DELETE", "/api/users"); ok {
		t.Fatal("DELETE should deny")
	}
	if ok, _ := MatchHTTP(pack, "POST", "/"); ok {
		t.Fatal("POST should deny")
	}
}

func TestMatchHTTPDenylist(t *testing.T) {
	pack := HTTPPack{Mode: "denylist", Rules: []string{"* /admin*", "DELETE *"}}
	if ok, _ := MatchHTTP(pack, "GET", "/api"); !ok {
		t.Fatal("GET /api")
	}
	if ok, reason := MatchHTTP(pack, "GET", "/admin/users"); ok {
		t.Fatalf("admin GET should deny: %s", reason)
	}
	if ok, _ := MatchHTTP(pack, "DELETE", "/api/users/1"); ok {
		t.Fatal("DELETE should deny")
	}
}

func TestMatchHTTPPathGlob(t *testing.T) {
	pack := HTTPPack{Mode: "allowlist", Rules: []string{"GET /api/tickets*", "POST /api/tickets"}}
	if ok, _ := MatchHTTP(pack, "GET", "/api/tickets/42?x=1"); !ok {
		t.Fatal("GET tickets id")
	}
	if ok, _ := MatchHTTP(pack, "POST", "/api/tickets"); !ok {
		t.Fatal("POST tickets")
	}
	if ok, _ := MatchHTTP(pack, "POST", "/api/tickets/42"); ok {
		t.Fatal("POST id should deny")
	}
	if ok, _ := MatchHTTP(pack, "GET", "/other"); ok {
		t.Fatal("/other")
	}
}

func TestMatchHTTPEmptyAllowlist(t *testing.T) {
	pack := HTTPPack{Mode: "allowlist"}
	if ok, _ := MatchHTTP(pack, "GET", "/"); ok {
		t.Fatal("empty allowlist")
	}
}

func TestHTTPOperation(t *testing.T) {
	if HTTPOperation("GET") != "" {
		t.Fatal("get")
	}
	if HTTPOperation("POST") != "http.write" {
		t.Fatal("post")
	}
	if HTTPOperation("DELETE") != "http.delete" {
		t.Fatal("delete")
	}
}

func TestNormalizeHTTPRules(t *testing.T) {
	got := normalizeHTTPRules([]string{"get /api/*", "/health", "DELETE *", "get /api/*"})
	if len(got) != 3 {
		t.Fatalf("%v", got)
	}
	if got[0] != "GET /api/*" || got[1] != "* /health" || got[2] != "DELETE *" {
		t.Fatalf("%v", got)
	}
}
