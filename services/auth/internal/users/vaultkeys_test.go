package users

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseVaultPrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	got, pub, fp, err := parseVaultPrivateKey(string(pem.EncodeToMemory(block)))
	if err != nil {
		t.Fatal(err)
	}
	if fp == "" || !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Fatalf("pub=%q fp=%q", pub, fp)
	}
	if ssh.FingerprintSHA256(got.PublicKey()) != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatal("fingerprint mismatch")
	}
	if _, _, _, err := parseVaultPrivateKey(""); err == nil {
		t.Fatal("empty key accepted")
	}
	if _, _, _, err := parseVaultPrivateKey("not-a-key"); err == nil {
		t.Fatal("garbage accepted")
	}
}
