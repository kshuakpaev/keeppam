package pades

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SignHashFunc signs a PKCS#1 v1.5 digest (SHA-256) for CMS.
type SignHashFunc func(hash []byte) ([]byte, error)

// LoadCertOnly loads leaf + chain without a local private key (PKCS#11 path).
func LoadCertOnly(certFile string) (*Signer, error) {
	pem, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("pades: read cert: %w", err)
	}
	certs, err := parsePEMCerts(pem)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("pades: empty certificate")
	}
	var chain []*x509.Certificate
	for _, c := range certs[1:] {
		chain = append(chain, c)
	}
	return &Signer{Cert: certs[0], Chain: chain, PKCS11: true}, nil
}

func parsePEMCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	tlsCert, err := tls.X509KeyPair(pemBytes, pemBytes)
	if err == nil && len(tlsCert.Certificate) > 0 {
		return parseCertDER(tlsCert.Certificate)
	}
	var out []*x509.Certificate
	rest := pemBytes
	for {
		block, remain := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			rest = remain
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pades: parse cert: %w", err)
		}
		out = append(out, c)
		rest = remain
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pades: no PEM certificate")
	}
	return out, nil
}

func parseCertDER(raw [][]byte) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(raw))
	for _, der := range raw {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("pades: parse cert: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}

// AttachPKCS11Helper wires HSM signing via external helper (CGO-free).
func AttachPKCS11Helper(s *Signer, helper, module, label, pin string) error {
	if s == nil {
		return fmt.Errorf("pades: empty signer")
	}
	helper = strings.TrimSpace(helper)
	if helper == "" {
		return fmt.Errorf("pades: empty PKCS#11 helper")
	}
	s.SignHash = pkcs11HelperSign(helper, module, label, pin)
	s.Key = nil
	s.PKCS11 = true
	return nil
}

func pkcs11HelperSign(helper, module, label, pin string) SignHashFunc {
	return func(hash []byte) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, helper)
		cmd.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString(hash))
		var env []string
		if module != "" {
			env = append(env, "KEEPPAM_PDF_PKCS11_MODULE="+module)
		}
		if label != "" {
			env = append(env, "KEEPPAM_PDF_PKCS11_LABEL="+label)
		}
		if pin != "" {
			env = append(env, "KEEPPAM_PDF_PKCS11_PIN="+pin)
		}
		if len(env) > 0 {
			cmd.Env = append(os.Environ(), env...)
		}
		out, err := cmd.Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return nil, fmt.Errorf("pkcs11 helper: %s", strings.TrimSpace(string(ee.Stderr)))
			}
			return nil, fmt.Errorf("pkcs11 helper: %w", err)
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
		if err != nil {
			return nil, fmt.Errorf("pkcs11 helper output: %w", err)
		}
		if len(sig) == 0 {
			return nil, fmt.Errorf("pkcs11 helper: empty signature")
		}
		return sig, nil
	}
}

// RSASignHash wraps a local RSA key as SignHashFunc (tests).
func RSASignHash(key *rsa.PrivateKey) SignHashFunc {
	return func(hash []byte) ([]byte, error) {
		return rsa.SignPKCS1v15(nil, key, crypto.SHA256, hash)
	}
}
