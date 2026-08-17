package pades

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	oidSignedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA256               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version            int
	SID                issuerAndSerial
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        []attribute `asn1:"optional,implicit,tag:0,set"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      []attribute `asn1:"optional,implicit,tag:1,set"`
}

type encapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	ContentInfo      encapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,implicit,tag:0,set"`
	SignerInfos      []signerInfo    `asn1:"set"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     signedData `asn1:"explicit,tag:0"`
}

type essCertIDv2 struct {
	HashAlgorithm algorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	IssuerSerial  essIssuerSerial `asn1:"optional"`
}

type essIssuerSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signingCertificateV2 struct {
	Certs []essCertIDv2
}

func nullAlg(oid asn1.ObjectIdentifier) algorithmIdentifier {
	return algorithmIdentifier{Algorithm: oid, Parameters: asn1.RawValue{Tag: asn1.TagNull}}
}

func sha256Alg() algorithmIdentifier {
	return algorithmIdentifier{Algorithm: oidSHA256}
}

func cadesBES(data []byte, s *Signer, at time.Time) ([]byte, error) {
	return buildCMS(data, s, at)
}

func buildCMS(data []byte, s *Signer, at time.Time) ([]byte, error) {
	if s == nil || s.Cert == nil || s.Key == nil {
		return nil, fmt.Errorf("pades: empty signer")
	}
	sum := sha256.Sum256(data)
	attrs, err := signedAttributes(s.Cert, sum[:], at)
	if err != nil {
		return nil, err
	}
	setDER, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		return nil, err
	}
	attrSum := sha256.Sum256(setDER)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.Key, crypto.SHA256, attrSum[:])
	if err != nil {
		return nil, err
	}
	var unsignedAttrs []attribute
	if url := strings.TrimSpace(s.TSAURL); url != "" {
		tsToken, err := fetchTimestamp(url, sig)
		if err != nil {
			return nil, err
		}
		ua, err := attrRaw(oidSignatureTimeStampToken, tsToken)
		if err != nil {
			return nil, err
		}
		unsignedAttrs = append(unsignedAttrs, ua)
	}
	certs := []asn1.RawValue{{FullBytes: s.Cert.Raw}}
	for _, c := range s.Chain {
		if c != nil && len(c.Raw) > 0 {
			certs = append(certs, asn1.RawValue{FullBytes: c.Raw})
		}
	}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: []algorithmIdentifier{sha256Alg()},
		ContentInfo:      encapsulatedContentInfo{ContentType: oidData},
		Certificates:     certs,
		SignerInfos: []signerInfo{{
			Version:            1,
			SID:                issuerAndSerial{Issuer: asn1.RawValue{FullBytes: s.Cert.RawIssuer}, Serial: s.Cert.SerialNumber},
			DigestAlgorithm:    sha256Alg(),
			SignedAttrs:        attrs,
			SignatureAlgorithm: nullAlg(oidRSAEncryption),
			Signature:          sig,
			UnsignedAttrs:      unsignedAttrs,
		}},
	}
	return asn1.Marshal(contentInfo{ContentType: oidSignedData, Content: sd})
}

func signedAttributes(cert *x509.Certificate, digest []byte, at time.Time) ([]attribute, error) {
	ct, err := attr(oidContentType, oidData)
	if err != nil {
		return nil, err
	}
	md, err := attr(oidMessageDigest, digest)
	if err != nil {
		return nil, err
	}
	st, err := attr(oidSigningTime, at.UTC().Truncate(time.Second))
	if err != nil {
		return nil, err
	}
	ess, err := attr(oidSigningCertificateV2, essV2(cert))
	if err != nil {
		return nil, err
	}
	return []attribute{ct, st, md, ess}, nil
}

func attr(oid asn1.ObjectIdentifier, value any) (attribute, error) {
	b, err := asn1.Marshal(value)
	if err != nil {
		return attribute{}, err
	}
	return attribute{Type: oid, Values: []asn1.RawValue{{FullBytes: b}}}, nil
}

func attrRaw(oid asn1.ObjectIdentifier, der []byte) (attribute, error) {
	return attribute{Type: oid, Values: []asn1.RawValue{{FullBytes: der}}}, nil
}

func essV2(cert *x509.Certificate) signingCertificateV2 {
	h := sha256.Sum256(cert.Raw)
	dirName := asn1.RawValue{Class: 2, Tag: 4, IsCompound: true, Bytes: cert.RawIssuer}
	gn, _ := asn1.Marshal(dirName)
	return signingCertificateV2{Certs: []essCertIDv2{{
		HashAlgorithm: sha256Alg(),
		CertHash:      h[:],
		IssuerSerial: essIssuerSerial{
			Issuer: asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: gn},
			Serial: cert.SerialNumber,
		},
	}}}
}
