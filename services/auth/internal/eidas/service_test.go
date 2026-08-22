package eidas

import (
	"context"
	"testing"

	"github.com/keeppam/auth/internal/pades"
)

func TestDemoQualifiedCert(t *testing.T) {
	cert, key, err := DemoQualifiedCert("eidas")
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := pades.CertQualified(cert, "eidas")
	if !ok {
		t.Fatal("demo eidas cert")
	}
	sig := &pades.Signer{Cert: cert, Key: key, TSAURL: "http://tsa", LTV: true, LTA: true}
	if err := pades.ValidateQualifiedExport(sig, "eidas", true); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeMode(t *testing.T) {
	if _, err := NormalizeMode("nope"); err == nil {
		t.Fatal("bad mode")
	}
	m, _ := NormalizeMode("qualified")
	if m != "qualified" {
		t.Fatal(m)
	}
}

func TestApplySignerOff(t *testing.T) {
	svc := &Service{}
	sig := &pades.Signer{}
	if err := svc.ApplySigner(context.Background(), sig); err != nil {
		t.Fatal(err)
	}
}
