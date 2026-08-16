package device

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net/url"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestNormalizeAndAllowed(t *testing.T) {
	out, err := Validate([]string{" tls ", "WEBAUTHN", "TLS", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[0] != "TLS" || out[1] != "WEBAUTHN" || out[2] != "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("%v", out)
	}
	if !Allowed(nil, nil) || !Allowed([]string{}, []string{"TLS"}) {
		t.Fatal("empty allow is any")
	}
	if Allowed([]string{"TLS"}, nil) || Allowed([]string{"TLS"}, []string{"WEBAUTHN"}) {
		t.Fatal("mismatch should deny")
	}
	if !Allowed([]string{"WEBAUTHN", "TLS"}, []string{"tls"}) {
		t.Fatal("class match")
	}
	if _, err := Validate([]string{"laptop"}); err == nil {
		t.Fatal("expected error")
	}
	out, err = Validate([]string{"SPIFFE", "spiffe://KeepPAM.local/ns/prod/*"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0] != "SPIFFE" || out[1] != "spiffe://keeppam.local/ns/prod/*" {
		t.Fatalf("%v", out)
	}
	if !Allowed([]string{"spiffe://keeppam.local/ns/prod/*"}, []string{"SPIFFE", "spiffe://keeppam.local/ns/prod/sa/api"}) {
		t.Fatal("spiffe glob")
	}
	if Allowed([]string{"spiffe://keeppam.local/ns/dev/*"}, []string{"spiffe://keeppam.local/ns/prod/sa/api"}) {
		t.Fatal("spiffe glob deny")
	}
	if _, err := Validate([]string{"spiffe://"}); err == nil {
		t.Fatal("invalid spiffe id")
	}
}

func TestFromTLS(t *testing.T) {
	if FromTLS(nil) != nil {
		t.Fatal("nil")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dev"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	got := FromTLS(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}})
	if len(got) != 2 || got[0] != "TLS" || len(got[1]) != 7+64 {
		t.Fatalf("%v", got)
	}
	sum := sha256.Sum256(der)
	if got[1] != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("fp %s", got[1])
	}

	uri, _ := url.Parse("spiffe://keeppam.local/workload/api")
	tmpl.URIs = []*url.URL{uri}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	got = FromTLS(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}})
	if !Allowed([]string{"SPIFFE"}, got) || !Allowed([]string{"spiffe://keeppam.local/workload/api"}, got) {
		t.Fatalf("spiffe from tls %v", got)
	}
	filtered := FilterTrustDomain(got, "other.local")
	if Allowed([]string{"SPIFFE"}, filtered) {
		t.Fatalf("trust domain should drop %v", filtered)
	}
}

func TestFromSSHKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got := FromSSHKey(pub)
	if len(got) != 2 || got[0] != "SSH" || !Allowed([]string{got[1]}, got) {
		t.Fatalf("%v", got)
	}
}
