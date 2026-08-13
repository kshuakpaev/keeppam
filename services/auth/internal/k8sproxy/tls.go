package k8sproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func LoadOrCreateTLS(certFile, keyFile, combinedPath, publicURL string) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	if combinedPath == "" {
		combinedPath = "/tmp/keeppam-k8s-tls.pem"
	}
	if b, err := os.ReadFile(combinedPath); err == nil && len(b) > 0 {
		certPEM, keyPEM, err := splitPEM(b)
		if err == nil {
			return tls.X509KeyPair(certPEM, keyPEM)
		}
	}
	hosts := []string{"localhost", "127.0.0.1"}
	if h := hostFromPublic(publicURL); h != "" {
		hosts = append(hosts, h)
	}
	certPEM, keyPEM, err := generateSelfSigned(hosts)
	if err != nil {
		return tls.Certificate{}, err
	}
	_ = os.WriteFile(combinedPath, append(certPEM, keyPEM...), 0o600)
	return tls.X509KeyPair(certPEM, keyPEM)
}

func hostFromPublic(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		return strings.Split(raw, "/")[0]
	}
	return host
}

func generateSelfSigned(hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "keeppam-k8s", Organization: []string{"KeepPAM"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     nil,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

func splitPEM(blob []byte) (certPEM, keyPEM []byte, err error) {
	rest := blob
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		b := pem.EncodeToMemory(block)
		switch block.Type {
		case "CERTIFICATE":
			certPEM = append(certPEM, b...)
		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
			keyPEM = append(keyPEM, b...)
		}
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, fmt.Errorf("combined pem must contain cert and key")
	}
	return certPEM, keyPEM, nil
}
