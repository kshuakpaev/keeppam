package pades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

var (
	oidTSTInfo                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSignatureTimeStampToken  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	oidTSTPolicy                = asn1.ObjectIdentifier{0, 4, 0, 2023, 1, 1}
)

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional,default:false"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString []asn1.RawValue `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Nonce          *big.Int `asn1:"optional"`
}

// fetchTimestamp requests an RFC3161 token over the SHA-256 imprint of data (CAdES: signature value).
func fetchTimestamp(url string, data []byte) ([]byte, error) {
	if url == "" {
		return nil, fmt.Errorf("pades: empty TSA URL")
	}
	sum := sha256.Sum256(data)
	nonce, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	reqDER, err := asn1.Marshal(timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: sha256Alg(),
			HashedMessage: sum[:],
		},
		Nonce:   nonce,
		CertReq: true,
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Accept", "application/timestamp-reply")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("pades: TSA request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pades: TSA HTTP %d", resp.StatusCode)
	}
	var tsResp timeStampResp
	if _, err := asn1.Unmarshal(body, &tsResp); err != nil {
		return nil, fmt.Errorf("pades: TSA response: %w", err)
	}
	if tsResp.Status.Status != 0 && tsResp.Status.Status != 1 {
		return nil, fmt.Errorf("pades: TSA status %d", tsResp.Status.Status)
	}
	if len(tsResp.TimeStampToken.FullBytes) == 0 {
		return nil, fmt.Errorf("pades: TSA empty token")
	}
	return tsResp.TimeStampToken.FullBytes, nil
}

// buildTimestampToken creates an RFC3161 CMS token (for tests / mock TSA).
func buildTimestampToken(tsa *Signer, imprint messageImprint, nonce *big.Int, at time.Time) ([]byte, error) {
	if tsa == nil || tsa.Cert == nil || tsa.Key == nil {
		return nil, fmt.Errorf("pades: empty TSA signer")
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	tstDER, err := asn1.Marshal(tstInfo{
		Version:        1,
		Policy:         oidTSTPolicy,
		MessageImprint: imprint,
		SerialNumber:   serial,
		GenTime:        at.UTC().Truncate(time.Second),
		Nonce:          nonce,
	})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(tstDER)
	ct, err := attr(oidContentType, oidTSTInfo)
	if err != nil {
		return nil, err
	}
	md, err := attr(oidMessageDigest, sum[:])
	if err != nil {
		return nil, err
	}
	attrs := []attribute{ct, md}
	setDER, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		return nil, err
	}
	attrSum := sha256.Sum256(setDER)
	sig, err := rsa.SignPKCS1v15(rand.Reader, tsa.Key, crypto.SHA256, attrSum[:])
	if err != nil {
		return nil, err
	}
	octetDER, err := asn1.Marshal(tstDER)
	if err != nil {
		return nil, err
	}
	eContent, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: octetDER})
	if err != nil {
		return nil, err
	}
	certs := []asn1.RawValue{{FullBytes: tsa.Cert.Raw}}
	for _, c := range tsa.Chain {
		if c != nil && len(c.Raw) > 0 {
			certs = append(certs, asn1.RawValue{FullBytes: c.Raw})
		}
	}
	sd := tstSignedData{
		Version:          3,
		DigestAlgorithms: []algorithmIdentifier{sha256Alg()},
		EncapContentInfo: tstEncapContentInfo{
			ContentType: oidTSTInfo,
			Content:     eContent,
		},
		Certificates: certs,
		SignerInfos: []signerInfo{{
			Version:            3,
			SID:                issuerAndSerial{Issuer: asn1.RawValue{FullBytes: tsa.Cert.RawIssuer}, Serial: tsa.Cert.SerialNumber},
			DigestAlgorithm:    sha256Alg(),
			SignedAttrs:        attrs,
			SignatureAlgorithm: nullAlg(oidRSAEncryption),
			Signature:          sig,
		}},
	}
	return asn1.Marshal(contentInfoTST{ContentType: oidSignedData, Content: sd})
}

type tstEncapContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"explicit,tag:0"`
}

type tstSignedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo tstEncapContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,implicit,tag:0,set"`
	SignerInfos      []signerInfo    `asn1:"set"`
}

type contentInfoTST struct {
	ContentType asn1.ObjectIdentifier
	Content     tstSignedData `asn1:"explicit,tag:0"`
}
