package crypto

import "testing"

func TestWipe(t *testing.T) {
	b := []byte("super-secret-key-material!!")
	Wipe(b)
	for _, c := range b {
		if c != 0 {
			t.Fatalf("not wiped: %q", b)
		}
	}
}

func TestWipeString(t *testing.T) {
	raw := []byte("vault-password-xyz")
	s := string(raw)
	Wipe(raw)
	WipeString(&s)
	if s != "" {
		t.Fatalf("string still set %q", s)
	}
}
