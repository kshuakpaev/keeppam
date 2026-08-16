package fips

import "testing"

func TestDefaultBackend(t *testing.T) {
	if Enabled() {
		t.Fatalf("default test binary should not be FIPS, got %s", Backend())
	}
	if Backend() != "go" && Backend() != "boringcrypto" && Backend() != "fips140" {
		t.Fatalf("backend %q", Backend())
	}
	if err := Enforce(false); err != nil {
		t.Fatal(err)
	}
	if err := Enforce(true); err == nil {
		t.Fatal("expected enforce error on standard crypto")
	}
}
