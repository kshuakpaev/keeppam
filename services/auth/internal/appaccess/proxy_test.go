package appaccess

import (
	"net/url"
	"testing"

	"github.com/google/uuid"
)

func TestRewritePrefixedLocation(t *testing.T) {
	up, err := url.Parse("https://app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	prefix := "/iso/sid/tok"

	cases := []struct {
		in, want string
	}{
		{"/dashboard", "/iso/sid/tok/dashboard"},
		{"/foo?x=1", "/iso/sid/tok/foo?x=1"},
		{"https://app.example.com/home", "/iso/sid/tok/home"},
		{"https://app.example.com:443/home", "/iso/sid/tok/home"},
		{"https://idp.example/oauth", "https://idp.example/oauth"},
		{"relative", "relative"},
		{"", ""},
	}
	for _, c := range cases {
		got := rewritePrefixedLocation(c.in, prefix, up)
		if got != c.want {
			t.Errorf("rewritePrefixedLocation(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsoProxyURL(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	got := IsoProxyURL("http://api:8080/", id, "deadbeef", "https://app.example.com/sso/login?next=/")
	want := "http://api:8080/iso/11111111-1111-1111-1111-111111111111/deadbeef/sso/login?next=/"
	if got != want {
		t.Fatalf("IsoProxyURL = %q, want %q", got, want)
	}
	if IsoProxyURL("", id, "tok", "") != "" {
		t.Fatal("empty base should yield empty URL")
	}
	root := IsoProxyURL("http://api:8080", id, "ab", "")
	if root != "http://api:8080/iso/11111111-1111-1111-1111-111111111111/ab/" {
		t.Fatalf("root path = %q", root)
	}
}
