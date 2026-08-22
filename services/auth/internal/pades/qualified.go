package pades

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
)

// eIDAS / ETSI qualified certificate policy OIDs (subset for on-prem validation).
var (
	oidQCPNaturalQES = asn1.ObjectIdentifier{0, 4, 0, 194, 121, 1, 1}
	oidQCPLegalQES   = asn1.ObjectIdentifier{0, 4, 0, 194, 121, 1, 2}
	oidQCPNatQES2016 = asn1.ObjectIdentifier{0, 4, 0, 194, 121, 2, 1}
	oidQCPLegQES2016 = asn1.ObjectIdentifier{0, 4, 0, 194, 121, 2, 2}
	oidQCPNQSCD      = asn1.ObjectIdentifier{0, 4, 0, 194, 112, 1, 2}
)

// FSTEC / GOST qualified signature policy OIDs (КЭП).
var (
	oidFSTECQES = asn1.ObjectIdentifier{1, 2, 643, 100, 113, 1}
)

// CertQualified reports whether leaf cert matches the regulatory profile.
func CertQualified(cert *x509.Certificate, profile string) (bool, string) {
	if cert == nil {
		return false, "empty certificate"
	}
	oids := certPolicyOIDs(cert)
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "fstec", "ru", "gost":
		for _, o := range oids {
			if o.Equal(oidFSTECQES) {
				return true, "FSTEC КЭП policy " + o.String()
			}
		}
		return false, "no FSTEC КЭП policy OID (1.2.643.100.113.1)"
	default:
		for _, o := range oids {
			if o.Equal(oidQCPNaturalQES) || o.Equal(oidQCPLegalQES) ||
				o.Equal(oidQCPNatQES2016) || o.Equal(oidQCPLegQES2016) ||
				o.Equal(oidQCPNQSCD) {
				return true, "eIDAS QES policy " + o.String()
			}
		}
		return false, "no eIDAS QES policy OID in certificate"
	}
}

var oidCertPolicies = asn1.ObjectIdentifier{2, 5, 29, 32}

func certPolicyOIDs(cert *x509.Certificate) []asn1.ObjectIdentifier {
	var out []asn1.ObjectIdentifier
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidCertPolicies) {
			out = append(out, parseCertPolicies(ext.Value)...)
		}
	}
	return out
}

type certPolicy struct {
	Policy asn1.ObjectIdentifier
}

func parseCertPolicies(der []byte) []asn1.ObjectIdentifier {
	var seq []certPolicy
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return nil
	}
	out := make([]asn1.ObjectIdentifier, 0, len(seq))
	for _, p := range seq {
		if len(p.Policy) > 0 {
			out = append(out, p.Policy)
		}
	}
	return out
}

// QualifiedLabel suffix for PDF Reason / compliance notes.
func QualifiedLabel(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "fstec", "ru", "gost":
		return "FSTEC qualified electronic signature (КЭП)"
	default:
		return "eIDAS qualified electronic signature (QES)"
	}
}

// ValidateQualifiedExport checks signer + profile for qualified mode export.
func ValidateQualifiedExport(s *Signer, profile string, requireBLTA bool) error {
	if s == nil || s.Cert == nil {
		return fmt.Errorf("pades: no signer configured")
	}
	ok, detail := CertQualified(s.Cert, profile)
	if !ok {
		return fmt.Errorf("qualified PDF: %s", detail)
	}
	if requireBLTA && !s.LTAEnabled() {
		return fmt.Errorf("qualified PDF requires PAdES-B-LTA (KEEPPAM_PDF_LTA + LTV + TSA)")
	}
	return nil
}
