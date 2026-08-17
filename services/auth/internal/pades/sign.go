package pades

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	SubFilter       = "ETSI.CAdES.detached"
	contentsReserve = 8192
)

// Signer is an RSA cert+key used for PAdES-B-B/B-T/B-LT/B-LTA.
type Signer struct {
	Cert     *x509.Certificate
	Key      *rsa.PrivateKey
	Chain    []*x509.Certificate
	TSAURL   string
	LTV      bool
	LTVDir   string
	LTVFetch bool
	LTA      bool
}

// LTVEnabled is B-LT: TSA + DSS validation data.
func (s *Signer) LTVEnabled() bool {
	return s != nil && s.LTV && strings.TrimSpace(s.TSAURL) != ""
}

// LTAEnabled is B-LTA: B-LT + document archive timestamp (ETSI.RFC3161).
func (s *Signer) LTAEnabled() bool {
	return s != nil && s.LTA && s.LTVEnabled()
}

// Profile returns PAdES baseline: B-B, B-T, B-LT, or B-LTA.
func (s *Signer) Profile() string {
	if s.LTAEnabled() {
		return "B-LTA"
	}
	if s.LTVEnabled() {
		return "B-LT"
	}
	if s != nil && strings.TrimSpace(s.TSAURL) != "" {
		return "B-T"
	}
	return "B-B"
}

// SignatureLabel is a human-readable profile for the PDF body.
func (s *Signer) SignatureLabel() string {
	switch s.Profile() {
	case "B-LTA":
		return "PAdES-B-LTA (CAdES + DSS + archive document timestamp)"
	case "B-LT":
		return "PAdES-B-LT (CAdES detached, RFC3161 timestamp, DSS)"
	case "B-T":
		return "PAdES-B-T (CAdES detached, RFC3161 timestamp)"
	default:
		return "PAdES-B-B (CAdES detached, no TSA/LTV)"
	}
}

func (s *Signer) CN() string {
	if s == nil || s.Cert == nil {
		return ""
	}
	if s.Cert.Subject.CommonName != "" {
		return s.Cert.Subject.CommonName
	}
	return s.Cert.Subject.String()
}

func Load(certFile, keyFile string) (*Signer, error) {
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("pades: load cert: %w", err)
	}
	key, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("pades: need RSA private key")
	}
	if len(tlsCert.Certificate) == 0 {
		return nil, fmt.Errorf("pades: empty certificate")
	}
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("pades: parse cert: %w", err)
	}
	var chain []*x509.Certificate
	for _, der := range tlsCert.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("pades: parse chain: %w", err)
		}
		chain = append(chain, c)
	}
	return &Signer{Cert: cert, Key: key, Chain: chain}, nil
}

// Sign appends a PAdES-B-B signature (incremental update) to a PDF 1.4 file.
func Sign(pdf []byte, s *Signer, at time.Time) ([]byte, error) {
	if len(pdf) < 8 || !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		return nil, fmt.Errorf("pades: not a PDF")
	}
	if s == nil {
		return nil, fmt.Errorf("pades: empty signer")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	} else {
		at = at.UTC()
	}
	out, meta, err := signWithReserve(pdf, s, at, reserveFor(s))
	if err != nil && strings.Contains(err.Error(), "cms too large") {
		out, meta, err = signWithReserve(pdf, s, at, reserveFor(s)*2)
	}
	if err != nil {
		return nil, err
	}
	if !s.LTVEnabled() {
		return out, nil
	}
	ltv, err := collectLTV(s)
	if err != nil {
		return nil, err
	}
	out, meta, err = appendDSS(out, meta, ltv)
	if err != nil {
		return nil, err
	}
	if !s.LTAEnabled() {
		return out, nil
	}
	return appendDocTimestamp(out, s, meta, at, contentsReserve)
}

func reserveFor(s *Signer) int {
	if s != nil && strings.TrimSpace(s.TSAURL) != "" {
		return contentsReserve * 2
	}
	return contentsReserve
}

func signWithReserve(pdf []byte, s *Signer, at time.Time, reserve int) ([]byte, signMeta, error) {
	startxref, size, err := parseTrailer(pdf)
	if err != nil {
		return nil, signMeta{}, err
	}
	pageBody, err := objectBody(pdf, 5)
	if err != nil {
		return nil, signMeta{}, fmt.Errorf("pades: first page: %w", err)
	}
	sigID := size
	fieldID := size + 1
	catalogID := size + 2

	var b bytes.Buffer
	b.Write(pdf)
	if !bytes.HasSuffix(pdf, []byte("\n")) {
		b.WriteByte('\n')
	}

	hexZeros := strings.Repeat("0", reserve*2)
	name := pdfLiteral(s.CN())
	reason := pdfLiteral("KeepPAM compliance report PAdES-" + s.Profile())
	m := at.Format("D:20060102150405Z")
	sigBody := fmt.Sprintf(
		"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /%s /ByteRange [0 0000000000 0000000000 0000000000] /Contents <%s> /M (%s) /Name (%s) /Reason (%s) >>\n",
		SubFilter, hexZeros, m, name, reason)
	pageBody = withAnnots(pageBody, fieldID)
	fieldBody := fmt.Sprintf(
		"<< /Type /Annot /Subtype /Widget /FT /Sig /T (KeepPAM) /F 132 /P 5 0 R /Rect [0 0 0 0] /V %d 0 R >>\n",
		sigID)
	catalogBody := fmt.Sprintf(
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [%d 0 R] /SigFlags 3 >> >>\n",
		fieldID)

	offPage := b.Len()
	fmt.Fprintf(&b, "5 0 obj\n%sendobj\n", pageBody)
	offSig := b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n%sendobj\n", sigID, sigBody)
	offField := b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n%sendobj\n", fieldID, fieldBody)
	offCat := b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n%sendobj\n", catalogID, catalogBody)

	xrefAt := b.Len()
	fmt.Fprintf(&b, "xref\n5 1\n%010d 00000 n \n%d 3\n%010d 00000 n \n%010d 00000 n \n%010d 00000 n \n",
		offPage, sigID, offSig, offField, offCat)
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root %d 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
		catalogID+1, catalogID, startxref, xrefAt)

	out := b.Bytes()
	brStart, contentsOpen, contentsClose, err := locateSigPlaceholders(out)
	if err != nil {
		return nil, signMeta{}, err
	}
	if contentsClose-contentsOpen-1 != reserve*2 {
		return nil, signMeta{}, fmt.Errorf("pades: contents width")
	}
	// ByteRange excludes <hex> including the angle brackets.
	a := contentsOpen
	c := contentsClose + 1
	d := len(out) - c
	br := fmt.Sprintf("/ByteRange [0 %010d %010d %010d]", a, c, d)
	if len(br) != len("/ByteRange [0 0000000000 0000000000 0000000000]") {
		return nil, signMeta{}, fmt.Errorf("pades: byterange width")
	}
	copy(out[brStart:brStart+len(br)], []byte(br))

	toSign := make([]byte, 0, a+d)
	toSign = append(toSign, out[:a]...)
	toSign = append(toSign, out[c:]...)
	cms, err := buildCMS(toSign, s, at)
	if err != nil {
		return nil, signMeta{}, err
	}
	if len(cms) > reserve {
		return nil, signMeta{}, fmt.Errorf("pades: cms too large (%d > %d)", len(cms), reserve)
	}
	hx := strings.ToUpper(hex.EncodeToString(cms))
	if len(hx)%2 != 0 {
		return nil, signMeta{}, fmt.Errorf("pades: odd hex")
	}
	padded := hx + strings.Repeat("0", reserve*2-len(hx))
	copy(out[contentsOpen+1:contentsClose], []byte(padded))
	return out, signMeta{catalogID: catalogID, fieldID: fieldID}, nil
}

func parseTrailer(pdf []byte) (startxref, size int, err error) {
	i := bytes.LastIndex(pdf, []byte("\nstartxref\n"))
	if i < 0 {
		return 0, 0, fmt.Errorf("pades: startxref")
	}
	rest := bytes.TrimSpace(pdf[i+len("\nstartxref\n"):])
	nl := bytes.IndexByte(rest, '\n')
	if nl < 0 {
		return 0, 0, fmt.Errorf("pades: startxref value")
	}
	startxref, err = strconv.Atoi(string(rest[:nl]))
	if err != nil {
		return 0, 0, fmt.Errorf("pades: startxref value")
	}
	tr := bytes.LastIndex(pdf, []byte("\ntrailer\n"))
	if tr < 0 || tr > i {
		return 0, 0, fmt.Errorf("pades: trailer")
	}
	chunk := string(pdf[tr:i])
	size, err = pdfIntAfter(chunk, "/Size")
	if err != nil {
		return 0, 0, err
	}
	if size < 6 {
		return 0, 0, fmt.Errorf("pades: pdf too small")
	}
	return startxref, size, nil
}

func pdfIntAfter(s, key string) (int, error) {
	k := strings.Index(s, key)
	if k < 0 {
		return 0, fmt.Errorf("pades: missing %s", key)
	}
	s = strings.TrimSpace(s[k+len(key):])
	n := 0
	for i, c := range s {
		if c < '0' || c > '9' {
			if i == 0 {
				return 0, fmt.Errorf("pades: bad %s", key)
			}
			break
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func objectBody(pdf []byte, id int) (string, error) {
	head := fmt.Sprintf("%d 0 obj\n", id)
	off := -1
	if bytes.HasPrefix(pdf, []byte(head)) {
		off = 0
	} else {
		off = bytes.Index(pdf, []byte("\n"+head))
		if off >= 0 {
			off++
		}
	}
	if off < 0 {
		return "", fmt.Errorf("object %d", id)
	}
	start := off + len(head)
	end := bytes.Index(pdf[start:], []byte("endobj"))
	if end < 0 {
		return "", fmt.Errorf("object %d end", id)
	}
	return string(pdf[start : start+end]), nil
}

func withAnnots(pageBody string, fieldID int) string {
	idx := strings.LastIndex(pageBody, ">>")
	if idx < 0 {
		return pageBody + fmt.Sprintf("/Annots [%d 0 R]\n", fieldID)
	}
	return pageBody[:idx] + fmt.Sprintf(" /Annots [%d 0 R] ", fieldID) + pageBody[idx:]
}

func locateSigPlaceholders(pdf []byte) (brStart, contentsOpen, contentsClose int, err error) {
	br := []byte("/ByteRange [0 0000000000 0000000000 0000000000]")
	brStart = bytes.LastIndex(pdf, br)
	if brStart < 0 {
		return 0, 0, 0, fmt.Errorf("pades: byterange placeholder")
	}
	marker := []byte("/Contents <")
	i := bytes.LastIndex(pdf, marker)
	if i < 0 {
		return 0, 0, 0, fmt.Errorf("pades: contents placeholder")
	}
	contentsOpen = i + len("/Contents ")
	if pdf[contentsOpen] != '<' {
		return 0, 0, 0, fmt.Errorf("pades: contents")
	}
	contentsClose = bytes.IndexByte(pdf[contentsOpen:], '>')
	if contentsClose < 0 {
		return 0, 0, 0, fmt.Errorf("pades: contents end")
	}
	contentsClose += contentsOpen
	return brStart, contentsOpen, contentsClose, nil
}

func pdfLiteral(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	return s
}
