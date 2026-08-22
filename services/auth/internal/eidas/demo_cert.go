package eidas

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// DemoQualifiedCert returns a self-signed cert with eIDAS QES policy OID (acceptance/lab only).
func DemoQualifiedCert(profile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	policyOID := asn1.ObjectIdentifier{0, 4, 0, 194, 121, 2, 1}
	if profile == "fstec" {
		policyOID = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 1}
	}
	policiesDER, err := asn1.Marshal([]certPolicy{{Policy: policyOID}})
	if err != nil {
		return nil, nil, err
	}
	cn := "KeepPAM Demo QES"
	if profile == "fstec" {
		cn = "KeepPAM Demo KEP"
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"KeepPAM Lab"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		ExtraExtensions: []pkix.Extension{{
			Id:    []asn1.ObjectIdentifier{{2, 5, 29, 32}}[0],
			Value: policiesDER,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

type certPolicy struct {
	Policy asn1.ObjectIdentifier
}
