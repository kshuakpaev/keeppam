package spiffe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func TestNormalizeID(t *testing.T) {
	id, ok := NormalizeID("SPIFFE://KeepPAM.local/ns/prod/sa/api")
	if !ok || id != "spiffe://keeppam.local/ns/prod/sa/api" {
		t.Fatalf("%s %v", id, ok)
	}
	if _, ok := NormalizeID("https://example"); ok {
		t.Fatal("https")
	}
	if !InTrustDomain(id, "keeppam.local") {
		t.Fatal("domain")
	}
	if InTrustDomain(id, "other") {
		t.Fatal("other")
	}
}

func TestMatch(t *testing.T) {
	id := "spiffe://keeppam.local/ns/prod/sa/api"
	if !Match(id, id) {
		t.Fatal("exact")
	}
	if !Match("spiffe://keeppam.local/ns/prod/*", id) {
		t.Fatal("prefix")
	}
	if Match("spiffe://keeppam.local/ns/dev/*", id) {
		t.Fatal("dev")
	}
}

func TestIDsFromCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://keeppam.local/workload/api")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	got := IDsFromCert(cert)
	if len(got) != 1 || got[0] != "spiffe://keeppam.local/workload/api" {
		t.Fatalf("%v", got)
	}
}
