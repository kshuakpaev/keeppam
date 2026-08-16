package geoip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClassifyLAN(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":            "LAN",
		"::1":                  "LAN",
		"10.1.2.3":             "LAN",
		"192.168.0.5":          "LAN",
		"172.16.9.1":           "LAN",
		"169.254.1.1":          "LAN",
		"127.0.0.1:2222":       "LAN",
		"8.8.8.8":              "",
		"2001:4860:4860::8888": "",
		"":                     "",
		"not-an-ip":            "",
	}
	for ip, want := range cases {
		if got := Classify(ip); got != want {
			t.Fatalf("%s: got %q want %q", ip, got, want)
		}
	}
}

func TestCountryWithoutDB(t *testing.T) {
	l := New("")
	if l.Loaded() {
		t.Fatal("empty path should not load")
	}
	if got := l.Country("10.0.0.1"); got != "LAN" {
		t.Fatalf("lan %q", got)
	}
	if got := l.Country("1.1.1.1"); got != "" {
		t.Fatalf("public without db %q", got)
	}
}

func TestAllowed(t *testing.T) {
	if !Allowed(nil, "RU") || !Allowed([]string{}, "KZ") {
		t.Fatal("empty allowlist is any")
	}
	if !Allowed([]string{"ru", "LAN"}, "LAN") {
		t.Fatal("LAN")
	}
	if Allowed([]string{"RU", "KZ"}, "") {
		t.Fatal("unknown public must fail closed")
	}
	if Allowed([]string{"RU"}, "US") {
		t.Fatal("mismatch")
	}
}

func TestValidateCountries(t *testing.T) {
	out, err := ValidateCountries([]string{" ru ", "LAN", "RU", "kz"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[0] != "RU" || out[1] != "LAN" || out[2] != "KZ" {
		t.Fatalf("%v", out)
	}
	if _, err := ValidateCountries([]string{"Russia"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestDemoMMDB(t *testing.T) {
	path := t.TempDir() + "/demo.mmdb"
	if err := WriteDemoMMDB(path); err != nil {
		t.Fatal(err)
	}
	l := New(path)
	if !l.Loaded() || l.DatabaseType() != DemoDatabaseType {
		t.Fatalf("loaded=%v type=%q", l.Loaded(), l.DatabaseType())
	}
	if got := l.Country("8.8.8.8"); got != "US" {
		t.Fatalf("google %q", got)
	}
	if got := l.Country("77.88.8.8"); got != "RU" {
		t.Fatalf("yandex %q", got)
	}
	if got := l.Country("10.1.2.3"); got != "LAN" {
		t.Fatalf("lan %q", got)
	}
	if got := l.Country("9.9.9.9"); got != "US" {
		t.Fatalf("quad9 %q", got)
	}
}

func TestRequestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.9:1234"
	r.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.9")
	if got := RequestClientIP(r, nil); got != "10.0.0.9" {
		t.Fatalf("untrusted %q", got)
	}
	if got := RequestClientIP(r, ParseProxyCIDRs("10.0.0.0/8")); got != "8.8.8.8" {
		t.Fatalf("xff %q", got)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "203.0.113.9:9"
	r2.Header.Set("X-Forwarded-For", "8.8.8.8")
	if got := RequestClientIP(r2, ParseProxyCIDRs("10.0.0.0/8")); got != "203.0.113.9" {
		t.Fatalf("public client %q", got)
	}
}
