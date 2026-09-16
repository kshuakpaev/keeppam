package filevault

import "testing"

func TestSanitizeName(t *testing.T) {
	if got := sanitizeName(`..\secret.txt`); got != "secret.txt" {
		t.Fatalf("got %q", got)
	}
	if got := sanitizeName("/tmp/a.bin"); got != "a.bin" {
		t.Fatalf("got %q", got)
	}
	if sanitizeName("") != "" {
		t.Fatal("empty should stay empty")
	}
	if sanitizeName(string([]byte{0xff, 0xfe})) != "" {
		t.Fatal("invalid utf-8")
	}
}
