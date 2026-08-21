package auth

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"
)

func TestCertIdentities(t *testing.T) {
	cert := &x509.Certificate{
		Subject:         pkix.Name{CommonName: "Ops.User"},
		EmailAddresses:  []string{"ops@example.com", "OPS@example.com"},
		DNSNames:        []string{"ops.user", "Ops.User"},
	}
	got := CertIdentities(cert)
	want := []string{"ops.user", "ops@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	if CertIdentities(nil) != nil {
		t.Fatal("nil cert")
	}
}
