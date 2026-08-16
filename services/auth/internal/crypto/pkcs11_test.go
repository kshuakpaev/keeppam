package crypto

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestPKCS11TokenRoundtrip(t *testing.T) {
	kek := bytes32(0x11)
	dek := bytes32(0x22)
	dir := t.TempDir()
	token := filepath.Join(dir, "token.json")
	if err := InitPKCS11Token(token, "pin-secret", "KeepPAM", "keeppam-kek", kek); err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapDEKWithKEK(kek, dek)
	if err != nil {
		t.Fatal(err)
	}
	p := PKCS11Provider{
		TokenFile:  token,
		PIN:        "pin-secret",
		Ciphertext: base64.StdEncoding.EncodeToString(wrapped),
	}
	got, err := p.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(dek) {
		t.Fatalf("dek mismatch")
	}
	p.PIN = "wrong"
	if _, err := p.Load(context.Background()); err == nil {
		t.Fatal("expected login failed")
	}
}

func TestPKCS11TokenWorldReadable(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "token.json")
	if err := InitPKCS11Token(token, "pin", "", "", bytes32(1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(token, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := UnlockPKCS11Token(token, "pin"); err == nil {
		t.Fatal("expected mode error")
	}
}

func TestParsePKCS11URI(t *testing.T) {
	u, err := ParsePKCS11URI("pkcs11:token=KeepPAM;object=keeppam-kek;type=secret?module-path=/usr/lib64/softhsm/libsofthsm2.so&pin-source=/run/pin")
	if err != nil {
		t.Fatal(err)
	}
	if u.TokenLabel != "KeepPAM" || u.KeyLabel != "keeppam-kek" {
		t.Fatalf("%+v", u)
	}
	if u.Module != "/usr/lib64/softhsm/libsofthsm2.so" || u.PINSource != "/run/pin" {
		t.Fatalf("%+v", u)
	}
	if _, err := ParsePKCS11URI("https://nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestPKCS11Helper(t *testing.T) {
	dek := bytes32(0x33)
	dir := t.TempDir()
	helper := filepath.Join(dir, "unwrap.sh")
	script := "#!/bin/sh\nprintf '%s' '" + base64.StdEncoding.EncodeToString(dek) + "'\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	p := PKCS11Provider{Helper: helper, Ciphertext: "ignored"}
	got, err := p.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(dek) {
		t.Fatalf("helper dek mismatch")
	}
}

func TestNewPKCS11FromEnv(t *testing.T) {
	t.Setenv("KEEPPAM_DATA_KEY_SOURCE", "pkcs11")
	t.Setenv("KEEPPAM_PKCS11_TOKEN_FILE", "")
	t.Setenv("KEEPPAM_PKCS11_HELPER", "")
	t.Setenv("KEEPPAM_PKCS11_MODULE", "")
	t.Setenv("KEEPPAM_PKCS11_URI", "")
	if _, err := NewPKCS11FromEnv(); err == nil {
		t.Fatal("expected error")
	}
	dir := t.TempDir()
	token := filepath.Join(dir, "token.json")
	kek, dek := bytes32(0x44), bytes32(0x55)
	if err := InitPKCS11Token(token, "p", "t", "k", kek); err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapDEKWithKEK(kek, dek)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEEPPAM_PKCS11_TOKEN_FILE", token)
	t.Setenv("KEEPPAM_PKCS11_PIN", "p")
	t.Setenv("KEEPPAM_KMS_CIPHERTEXT", base64.StdEncoding.EncodeToString(wrapped))
	kp, err := NewPKCS11FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	got, err := kp.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(dek) {
		t.Fatal("env load")
	}
}

func bytes32(v byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = v
	}
	return b
}
