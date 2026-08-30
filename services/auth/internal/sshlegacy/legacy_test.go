package sshlegacy

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestApplyClientAppendsLegacyWithoutReorderingHostKeys(t *testing.T) {
	cfg := &ssh.ClientConfig{}
	ApplyClient(cfg)
	if len(cfg.KeyExchanges) < 2 {
		t.Fatalf("kex %v", cfg.KeyExchanges)
	}
	if cfg.KeyExchanges[0] == ssh.InsecureKeyExchangeDH1SHA1 {
		t.Fatal("legacy group1 must not be the preferred KEX")
	}
	found := false
	for _, k := range cfg.KeyExchanges {
		if k == ssh.InsecureKeyExchangeDH1SHA1 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("missing diffie-hellman-group1-sha1")
	}
	found3DES := false
	for _, c := range cfg.Ciphers {
		if c == ssh.InsecureCipherTripleDESCBC {
			found3DES = true
			break
		}
	}
	if !found3DES {
		t.Fatal("missing 3des-cbc")
	}
	if len(cfg.HostKeyAlgorithms) != 0 {
		t.Fatalf("HostKeyAlgorithms must stay empty (library default order); got %v", cfg.HostKeyAlgorithms)
	}
}

func TestApplyServerSetsPublicKeyAlgos(t *testing.T) {
	cfg := &ssh.ServerConfig{}
	ApplyServer(cfg)
	if len(cfg.PublicKeyAuthAlgorithms) == 0 || len(cfg.KeyExchanges) == 0 {
		t.Fatal("server legacy algos not applied")
	}
}
