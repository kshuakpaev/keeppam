package sshproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestHostKeyAlgorithmsForPinsEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	got := hostKeyAlgorithmsFor(signer.PublicKey().Marshal())
	if len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("got %v", got)
	}
}

func TestHostKeyAlgorithmsForEmpty(t *testing.T) {
	if hostKeyAlgorithmsFor(nil) != nil {
		t.Fatal("expected nil")
	}
}
