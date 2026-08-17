package pades

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "KeepPAM Test PAdES", Organization: []string{"KeepPAM"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{Cert: cert, Key: key}
}

func TestSignPAdES(t *testing.T) {
	s := testSigner(t)
	raw := minimalPDF(t)
	at := time.Date(2026, 8, 17, 6, 0, 0, 0, time.UTC)
	out, err := Sign(raw, s, at)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("/SubFilter /ETSI.CAdES.detached")) {
		t.Fatal("subfilter")
	}
	if !bytes.Contains(out, []byte("/SigFlags 3")) {
		t.Fatal("acroform")
	}
	if !bytes.HasPrefix(out, raw) {
		t.Fatal("incremental prefix")
	}
	if bytes.Count(out, []byte("%%EOF")) < 2 {
		t.Fatal("incremental eof")
	}
	cms, covered, err := extractCMS(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCAdES(cms, covered, s.Cert); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAndSignFile(t *testing.T) {
	s := testSigner(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Cert.Raw}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(s.Key)}), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CN() != "KeepPAM Test PAdES" {
		t.Fatal(loaded.CN())
	}
	out, err := Sign(minimalPDF(t), loaded, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("KeepPAM Test PAdES")) {
		t.Fatal("name")
	}
}

func TestSignPAdESWithLTA(t *testing.T) {
	s := testSigner(t)
	tsa := testSigner(t)
	srv := mockTSAServer(t, tsa)
	defer srv.Close()

	dir := t.TempDir()
	ocspDir := filepath.Join(dir, "ocsp")
	if err := os.MkdirAll(ocspDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ocspDir, "demo.der"), []byte{0x30, 0x03, 0x02, 0x01, 0x00}, 0644); err != nil {
		t.Fatal(err)
	}

	s.TSAURL = srv.URL
	s.LTV = true
	s.LTA = true
	s.LTVDir = dir
	s.LTVFetch = false
	out, err := Sign(minimalPDF(t), s, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("PAdES-B-LTA")) {
		t.Fatal("profile reason")
	}
	if !bytes.Contains(out, []byte("/SubFilter /ETSI.RFC3161")) {
		t.Fatal("archive subfilter")
	}
	if !bytes.Contains(out, []byte("/Type /DSS")) {
		t.Fatal("dss")
	}
	if bytes.Count(out, []byte("%%EOF")) < 4 {
		t.Fatal("lta incremental eof")
	}
}

func TestSignPAdESWithLTV(t *testing.T) {
	s := testSigner(t)
	tsa := testSigner(t)
	srv := mockTSAServer(t, tsa)
	defer srv.Close()

	dir := t.TempDir()
	ocspDir := filepath.Join(dir, "ocsp")
	if err := os.MkdirAll(ocspDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ocspDir, "demo.der"), []byte{0x30, 0x03, 0x02, 0x01, 0x00}, 0644); err != nil {
		t.Fatal(err)
	}

	s.TSAURL = srv.URL
	s.LTV = true
	s.LTVDir = dir
	s.LTVFetch = false
	out, err := Sign(minimalPDF(t), s, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("PAdES-B-LT")) {
		t.Fatal("profile reason")
	}
	if !bytes.Contains(out, []byte("/Type /DSS")) {
		t.Fatal("dss")
	}
	if !bytes.Contains(out, []byte("/Certs [")) {
		t.Fatal("dss certs")
	}
	if !bytes.Contains(out, []byte("/OCSPs [")) {
		t.Fatal("dss ocsp")
	}
	if bytes.Count(out, []byte("%%EOF")) < 3 {
		t.Fatal("dss incremental eof")
	}
}

func TestSignPAdESWithTSA(t *testing.T) {
	s := testSigner(t)
	tsa := testSigner(t)
	srv := mockTSAServer(t, tsa)
	defer srv.Close()

	s.TSAURL = srv.URL
	raw := minimalPDF(t)
	at := time.Date(2026, 8, 17, 7, 0, 0, 0, time.UTC)
	out, err := Sign(raw, s, at)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("PAdES-B-T")) {
		t.Fatal("profile reason")
	}
	cms, covered, err := extractCMS(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCAdES(cms, covered, s.Cert); err != nil {
		t.Fatal(err)
	}
	if err := verifySignatureTimestamp(cms); err != nil {
		t.Fatal(err)
	}
}

func mockTSAServer(t *testing.T, tsa *Signer) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req timeStampReq
		if _, err := asn1.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		token, err := buildTimestampToken(tsa, req.MessageImprint, req.Nonce, time.Now().UTC())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respDER, err := asn1.Marshal(timeStampResp{
			Status:         pkiStatusInfo{Status: 0},
			TimeStampToken: asn1.RawValue{FullBytes: token},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(respDER)
	}))
}

func verifySignatureTimestamp(cmsDER []byte) error {
	var ci contentInfo
	if _, err := asn1.Unmarshal(cmsDER, &ci); err != nil {
		return err
	}
	if len(ci.Content.SignerInfos) != 1 {
		return fmt.Errorf("signerInfos")
	}
	si := ci.Content.SignerInfos[0]
	for _, a := range si.UnsignedAttrs {
		if a.Type.Equal(oidSignatureTimeStampToken) && len(a.Values) > 0 && len(a.Values[0].FullBytes) > 0 {
			return nil
		}
	}
	return fmt.Errorf("no signature timestamp")
}

func TestSignRejectsNonPDF(t *testing.T) {
	if _, err := Sign([]byte("not pdf"), testSigner(t), time.Time{}); err == nil {
		t.Fatal("expected error")
	}
}

func minimalPDF(t *testing.T) []byte {
	t.Helper()
	raw := "BT /F1 12 Tf 72 720 Td (KeepPAM) Tj ET\n"
	type obj struct {
		id   int
		body string
	}
	objs := []obj{
		{1, "<< /Type /Catalog /Pages 2 0 R >>\n"},
		{2, "<< /Type /Pages /Count 1 /Kids [5 0 R] >>\n"},
		{3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\n"},
		{4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\n"},
		{5, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents 6 0 R >>\n"},
		{6, fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream\n", len(raw), raw)},
	}
	var buf strings.Builder
	buf.WriteString("%PDF-1.4\n%\x80\x80\x80\x80\n")
	offsets := make([]int, 7)
	for _, o := range objs {
		offsets[o.id] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%sendobj\n", o.id, o.body)
	}
	startxref := buf.Len()
	buf.WriteString("xref\n0 7\n0000000000 65535 f \n")
	for id := 1; id < 7; id++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[id])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", startxref)
	return []byte(buf.String())
}

func extractCMS(pdf []byte) (cms, covered []byte, err error) {
	marker := []byte("/Contents <")
	i := bytes.LastIndex(pdf, marker)
	if i < 0 {
		return nil, nil, fmt.Errorf("contents")
	}
	open := i + len("/Contents ")
	close := bytes.IndexByte(pdf[open:], '>')
	if close < 0 {
		return nil, nil, fmt.Errorf("contents end")
	}
	close += open
	cms, err = hex.DecodeString(string(pdf[open+1 : close]))
	if err != nil {
		return nil, nil, err
	}
	br := bytes.LastIndex(pdf, []byte("/ByteRange ["))
	if br < 0 {
		return nil, nil, fmt.Errorf("byterange")
	}
	end := bytes.IndexByte(pdf[br:], ']')
	if end < 0 {
		return nil, nil, fmt.Errorf("byterange end")
	}
	fields := strings.Fields(strings.Trim(string(pdf[br+len("/ByteRange ["):br+end]), "[] "))
	if len(fields) != 4 {
		return nil, nil, fmt.Errorf("byterange fields %q", fields)
	}
	a, err1 := strconv.Atoi(fields[1])
	c, err2 := strconv.Atoi(fields[2])
	if err1 != nil || err2 != nil || a < 0 || c > len(pdf) || a > c {
		return nil, nil, fmt.Errorf("byterange values")
	}
	covered = append(append([]byte{}, pdf[:a]...), pdf[c:]...)
	return cms, covered, nil
}

func verifyCAdES(der, content []byte, cert *x509.Certificate) error {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return err
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return fmt.Errorf("not signedData")
	}
	if len(ci.Content.SignerInfos) != 1 {
		return fmt.Errorf("signerInfos")
	}
	si := ci.Content.SignerInfos[0]
	setDER, err := asn1.MarshalWithParams(si.SignedAttrs, "set")
	if err != nil {
		return err
	}
	sum := sha256.Sum256(setDER)
	if err := rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, sum[:], si.Signature); err != nil {
		return err
	}
	want := sha256.Sum256(content)
	var got []byte
	var hasESS bool
	for _, a := range si.SignedAttrs {
		if a.Type.Equal(oidMessageDigest) && len(a.Values) > 0 {
			if _, err := asn1.Unmarshal(a.Values[0].FullBytes, &got); err != nil {
				return err
			}
		}
		if a.Type.Equal(oidSigningCertificateV2) {
			hasESS = true
		}
	}
	if !bytes.Equal(got, want[:]) {
		return fmt.Errorf("message-digest")
	}
	if !hasESS {
		return fmt.Errorf("no ess")
	}
	return nil
}
