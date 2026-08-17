package pades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

type ltvBundle struct {
	Certs [][]byte
	OCSPs [][]byte
	CRLs  [][]byte
}

func collectLTV(s *Signer) (ltvBundle, error) {
	if s == nil || s.Cert == nil {
		return ltvBundle{}, fmt.Errorf("pades: empty signer")
	}
	var b ltvBundle
	seen := map[string]struct{}{}
	addCert := func(raw []byte) {
		if len(raw) == 0 {
			return
		}
		sum := sha256.Sum256(raw)
		key := string(sum[:])
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		b.Certs = append(b.Certs, append([]byte(nil), raw...))
	}
	addCert(s.Cert.Raw)
	for _, c := range s.Chain {
		if c != nil {
			addCert(c.Raw)
		}
	}
	if dir := strings.TrimSpace(s.LTVDir); dir != "" {
		if err := loadLTVDir(dir, &b); err != nil {
			return ltvBundle{}, err
		}
	}
	if s.LTVFetch {
		chain := append([]*x509.Certificate{s.Cert}, s.Chain...)
		for _, cert := range chain {
			if cert == nil {
				continue
			}
			issuer := issuerFor(cert, chain)
			if issuer == nil {
				continue
			}
			if ocspDER, err := fetchOCSP(cert, issuer); err == nil && len(ocspDER) > 0 {
				b.OCSPs = append(b.OCSPs, ocspDER)
			}
			if crlDER, err := fetchCRL(cert); err == nil && len(crlDER) > 0 {
				b.CRLs = append(b.CRLs, crlDER)
			}
		}
	}
	return b, nil
}

func issuerFor(cert *x509.Certificate, chain []*x509.Certificate) *x509.Certificate {
	if cert == nil {
		return nil
	}
	if cert.CheckSignatureFrom(cert) == nil {
		return nil
	}
	for _, c := range chain {
		if c != nil && cert.CheckSignatureFrom(c) == nil {
			return c
		}
	}
	return nil
}

func loadLTVDir(dir string, b *ltvBundle) error {
	for _, sub := range []struct {
		name string
		dst  *[][]byte
	}{
		{"certs", &b.Certs},
		{"ocsp", &b.OCSPs},
		{"crl", &b.CRLs},
	} {
		if err := loadDERDir(filepath.Join(dir, sub.name), sub.dst); err != nil {
			return err
		}
	}
	return nil
}

func loadDERDir(dir string, dst *[][]byte) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("pades: ltv dir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := readDERFile(path)
		if err != nil {
			return fmt.Errorf("pades: ltv %s: %w", path, err)
		}
		if len(raw) > 0 {
			*dst = append(*dst, raw)
		}
	}
	return nil
}

func readDERFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(data); block != nil {
		return block.Bytes, nil
	}
	return data, nil
}

func fetchOCSP(cert, issuer *x509.Certificate) ([]byte, error) {
	if cert == nil || issuer == nil || len(cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("pades: no ocsp url")
	}
	reqDER, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, u := range cert.OCSPServer {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(reqDER))
		if err != nil {
			continue
		}
		httpReq.Header.Set("Content-Type", "application/ocsp-request")
		httpReq.Header.Set("Accept", "application/ocsp-response")
		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		if _, err := ocsp.ParseResponse(body, issuer); err != nil {
			continue
		}
		return body, nil
	}
	return nil, fmt.Errorf("pades: ocsp fetch failed")
}

func fetchCRL(cert *x509.Certificate) ([]byte, error) {
	if cert == nil || len(cert.CRLDistributionPoints) == 0 {
		return nil, fmt.Errorf("pades: no crl url")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, u := range cert.CRLDistributionPoints {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || len(body) == 0 {
			continue
		}
		if block, _ := pem.Decode(body); block != nil {
			body = block.Bytes
		}
		if _, err := x509.ParseCRL(body); err != nil {
			continue
		}
		return body, nil
	}
	return nil, fmt.Errorf("pades: crl fetch failed")
}
