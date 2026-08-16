package spiffe

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strings"
)

const Scheme = "spiffe://"

type Identity struct {
	IDs    []string
	Bundle *x509.CertPool
}

func ValidID(raw string) bool {
	id, ok := NormalizeID(raw)
	return ok && id != ""
}

func NormalizeID(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if !strings.HasPrefix(s, Scheme) {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" {
		return "", false
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return "", false
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return "spiffe://" + u.Host + path, true
}

func InTrustDomain(id, domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return true
	}
	id, ok := NormalizeID(id)
	if !ok {
		return false
	}
	want := "spiffe://" + domain + "/"
	return id == "spiffe://"+domain || strings.HasPrefix(id, want) || id == "spiffe://"+domain+"/"
}

func IDsFromCert(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	for _, u := range cert.URIs {
		if u == nil {
			continue
		}
		id, ok := NormalizeID(u.String())
		if !ok {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func Match(pattern, id string) bool {
	got, ok := NormalizeID(id)
	if !ok {
		return false
	}
	raw := strings.ToLower(strings.TrimSpace(pattern))
	if strings.HasSuffix(raw, "*") {
		prefix := strings.TrimSuffix(raw, "*")
		if !strings.HasPrefix(prefix, Scheme) {
			return false
		}
		return strings.HasPrefix(got, prefix)
	}
	p, ok := NormalizeID(pattern)
	return ok && p == got
}

func LoadPEM(svidFile, bundleFile string) (Identity, error) {
	var id Identity
	if svidFile != "" {
		pemBytes, err := os.ReadFile(svidFile)
		if err != nil {
			return id, fmt.Errorf("spiffe svid: %w", err)
		}
		certs, err := parseCerts(pemBytes)
		if err != nil {
			return id, err
		}
		if len(certs) == 0 {
			return id, fmt.Errorf("spiffe svid: no certificates")
		}
		id.IDs = IDsFromCert(certs[0])
	}
	if bundleFile != "" {
		pemBytes, err := os.ReadFile(bundleFile)
		if err != nil {
			return id, fmt.Errorf("spiffe bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return id, fmt.Errorf("spiffe bundle: no certificates")
		}
		id.Bundle = pool
	}
	return id, nil
}

func parseCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("spiffe svid: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}
