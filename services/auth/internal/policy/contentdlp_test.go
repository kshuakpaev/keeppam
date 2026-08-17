package policy

import "testing"

func TestScanPIIEmailPAN(t *testing.T) {
	kinds, masked := ScanPII(`contact user@example.com card 4111111111111111`)
	if len(kinds) != 2 {
		t.Fatalf("kinds=%v masked=%q", kinds, masked)
	}
	if !containsKind(kinds, "email") || !containsKind(kinds, "pan") {
		t.Fatalf("kinds=%v", kinds)
	}
	if stringsContains(masked, "user@example.com") || stringsContains(masked, "4111111111111111") {
		t.Fatalf("leaked: %q", masked)
	}
	if !stringsContains(masked, "1111") {
		t.Fatalf("want last4: %q", masked)
	}
}

func TestScanPIINoFalsePAN(t *testing.T) {
	kinds, _ := ScanPII("order 1234567890123456")
	if containsKind(kinds, "pan") {
		t.Fatalf("luhn fail should not match: %v", kinds)
	}
}

func TestScanPIIPhoneSNILS(t *testing.T) {
	kinds, masked := ScanPII("call +7 999 123-45-67 snils 123-456-789 00")
	if !containsKind(kinds, "phone") || !containsKind(kinds, "snils") {
		t.Fatalf("kinds=%v masked=%q", kinds, masked)
	}
}

func TestApplyPIIAction(t *testing.T) {
	out, deny, kinds := ApplyPIIAction("mask", "a@b.co")
	if deny || len(kinds) != 1 || out == "a@b.co" {
		t.Fatalf("mask %q %v %v", out, deny, kinds)
	}
	_, deny, kinds = ApplyPIIAction("deny", "a@b.co")
	if !deny || len(kinds) != 1 {
		t.Fatalf("deny %v %v", deny, kinds)
	}
	s, deny, kinds := ApplyPIIAction("", "a@b.co")
	if deny || kinds != nil || s != "a@b.co" {
		t.Fatalf("off")
	}
}

func TestApplyPIIRowsDeny(t *testing.T) {
	rows := [][]string{{"ok", "user@example.com"}}
	_, deny, kinds := ApplyPIIRows("deny", rows)
	if !deny || !containsKind(kinds, "email") {
		t.Fatalf("%v %v", deny, kinds)
	}
	out, deny, _ := ApplyPIIRows("mask", rows)
	if deny || out[0][1] == "user@example.com" {
		t.Fatalf("%v %v", deny, out)
	}
}

func TestFilterHTTPBody(t *testing.T) {
	out, deny, kinds := FilterHTTPBody("mask", "application/json", []byte(`{"email":"a@b.co"}`))
	if deny || len(kinds) != 1 || string(out) == `{"email":"a@b.co"}` {
		t.Fatalf("%q %v %v", out, deny, kinds)
	}
	_, deny, _ = FilterHTTPBody("mask", "image/png", []byte("a@b.co"))
	if deny {
		t.Fatal("binary")
	}
}

func TestNormalizePIIAction(t *testing.T) {
	got, err := NormalizePIIAction(" MASK ")
	if err != nil || got != "mask" {
		t.Fatal(got, err)
	}
	if _, err := NormalizePIIAction("drop"); err == nil {
		t.Fatal("drop")
	}
}

func containsKind(kinds []string, want string) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}

func stringsContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
