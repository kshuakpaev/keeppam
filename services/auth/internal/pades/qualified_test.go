package pades

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestCertQualifiedEIDAS(t *testing.T) {
	cert := certWithPolicy(t, asn1.ObjectIdentifier{0, 4, 0, 194, 121, 2, 1})
	ok, _ := CertQualified(cert, "eidas")
	if !ok {
		t.Fatal("expected eIDAS qualified")
	}
	ok, _ = CertQualified(cert, "fstec")
	if ok {
		t.Fatal("fstec should reject eIDAS oid")
	}
}

func TestCertQualifiedFSTEC(t *testing.T) {
	cert := certWithPolicy(t, asn1.ObjectIdentifier{1, 2, 643, 100, 113, 1})
	ok, _ := CertQualified(cert, "fstec")
	if !ok {
		t.Fatal("expected FSTEC qualified")
	}
}

func TestValidateQualifiedExportRequiresBLTA(t *testing.T) {
	s := &Signer{Cert: certWithPolicy(t, asn1.ObjectIdentifier{0, 4, 0, 194, 121, 2, 1})}
	if err := ValidateQualifiedExport(s, "eidas", true); err == nil {
		t.Fatal("expected B-LTA requirement")
	}
	s.LTV = true
	s.LTA = true
	s.TSAURL = "http://tsa"
	if err := ValidateQualifiedExport(s, "eidas", true); err != nil {
		t.Fatal(err)
	}
}

func certWithPolicy(t *testing.T, oid asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	policiesDER, err := asn1.Marshal([]certPolicy{{Policy: oid}})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{
			Id:    []asn1.ObjectIdentifier{{2, 5, 29, 32}}[0],
			Value: policiesDER,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
