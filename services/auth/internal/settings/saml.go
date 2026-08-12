package settings

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/redis/go-redis/v9"
)

type samlRelayState struct {
	RequestID string `json:"request_id"`
}

type SAMLClaims struct {
	Subject  string
	Username string
	Email    string
	Name     string
}

func (s *Service) buildSAMLSP(ctx context.Context, cfg AuthSettings, needIDP bool) (*saml.ServiceProvider, error) {
	if cfg.PublicBaseURL == "" {
		return nil, fmt.Errorf("public_base_url is required for SAML")
	}
	enc, err := s.GetSAMLSPKeyEnc(ctx)
	if err != nil {
		return nil, err
	}
	pemBlob, err := s.env.Decrypt(enc)
	if err != nil {
		return nil, fmt.Errorf("saml sp key: %w", err)
	}
	certPEM, keyPEM, err := splitPEMCertKey(pemBlob)
	if err != nil {
		return nil, err
	}
	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("saml sp keypair: %w", err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, err
	}
	rsaKey, ok := keyPair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("saml sp key must be RSA")
	}

	metadataURL, _ := url.Parse(cfg.PublicBaseURL + "/api/v1/auth/saml/metadata")
	acsURL, _ := url.Parse(cfg.PublicBaseURL + "/api/v1/auth/saml/acs")
	entityID := cfg.SAMLSPEntityID
	if entityID == "" {
		entityID = metadataURL.String()
	}

	sp := &saml.ServiceProvider{
		EntityID:          entityID,
		Key:               rsaKey,
		Certificate:       keyPair.Leaf,
		MetadataURL:       *metadataURL,
		AcsURL:            *acsURL,
		AllowIDPInitiated: false,
	}
	if needIDP {
		idpMeta, err := s.loadIDPMetadata(ctx, cfg)
		if err != nil {
			return nil, err
		}
		sp.IDPMetadata = idpMeta
	}
	return sp, nil
}

func (s *Service) loadIDPMetadata(ctx context.Context, cfg AuthSettings) (*saml.EntityDescriptor, error) {
	if u := strings.TrimSpace(cfg.SAMLIdPMetadataURL); u != "" {
		parsed, err := url.Parse(u)
		if err != nil {
			return nil, fmt.Errorf("invalid idp metadata url")
		}
		return samlsp.FetchMetadata(ctx, http.DefaultClient, *parsed)
	}
	if strings.TrimSpace(cfg.SAMLIdPEntityID) == "" || strings.TrimSpace(cfg.SAMLIdPSSOURL) == "" || strings.TrimSpace(cfg.SAMLIdPCertPEM) == "" {
		return nil, fmt.Errorf("saml idp metadata_url or entity_id+sso_url+cert required")
	}
	block, _ := pem.Decode([]byte(cfg.SAMLIdPCertPEM))
	if block == nil {
		// allow raw base64 cert body
		raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(cfg.SAMLIdPCertPEM, "\n", ""))
		if err != nil {
			return nil, fmt.Errorf("invalid idp cert pem")
		}
		block = &pem.Block{Type: "CERTIFICATE", Bytes: raw}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse idp cert: %w", err)
	}
	return &saml.EntityDescriptor{
		EntityID: cfg.SAMLIdPEntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{
					ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
					KeyDescriptors: []saml.KeyDescriptor{{
						Use: "signing",
						KeyInfo: saml.KeyInfo{
							X509Data: saml.X509Data{
								X509Certificates: []saml.X509Certificate{{
									Data: base64.StdEncoding.EncodeToString(cert.Raw),
								}},
							},
						},
					}},
				},
				NameIDFormats: []saml.NameIDFormat{
					saml.EmailAddressNameIDFormat,
					saml.PersistentNameIDFormat,
					saml.UnspecifiedNameIDFormat,
				},
			},
			SingleSignOnServices: []saml.Endpoint{
				{Binding: saml.HTTPRedirectBinding, Location: cfg.SAMLIdPSSOURL},
				{Binding: saml.HTTPPostBinding, Location: cfg.SAMLIdPSSOURL},
			},
		}},
	}, nil
}

func splitPEMCertKey(blob []byte) (certPEM, keyPEM []byte, err error) {
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
		case "PRIVATE KEY", "RSA PRIVATE KEY":
			keyPEM = append(keyPEM, b...)
		}
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, fmt.Errorf("saml sp pem must contain certificate and private key")
	}
	return certPEM, keyPEM, nil
}

func (s *Service) SAMLMetadataXML(ctx context.Context, cfg AuthSettings) ([]byte, error) {
	sp, err := s.buildSAMLSP(ctx, cfg, false)
	if err != nil {
		return nil, err
	}
	return xml.MarshalIndent(sp.Metadata(), "", "  ")
}

func (s *Service) SAMLAuthRedirect(ctx context.Context, rdb *redis.Client, cfg AuthSettings) (*url.URL, error) {
	sp, err := s.buildSAMLSP(ctx, cfg, true)
	if err != nil {
		return nil, err
	}
	idpURL := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	binding := saml.HTTPRedirectBinding
	if idpURL == "" {
		idpURL = sp.GetSSOBindingLocation(saml.HTTPPostBinding)
		binding = saml.HTTPPostBinding
	}
	if idpURL == "" {
		return nil, fmt.Errorf("idp sso url not found in metadata")
	}
	req, err := sp.MakeAuthenticationRequest(idpURL, binding, saml.HTTPPostBinding)
	if err != nil {
		return nil, err
	}
	relay := randomToken(24)
	payload, _ := json.Marshal(samlRelayState{RequestID: req.ID})
	if err := rdb.Set(ctx, "saml:"+relay, payload, 10*time.Minute).Err(); err != nil {
		return nil, err
	}
	return req.Redirect(relay, sp)
}

func (s *Service) SAMLParseACS(ctx context.Context, rdb *redis.Client, cfg AuthSettings, r *http.Request) (SAMLClaims, error) {
	sp, err := s.buildSAMLSP(ctx, cfg, true)
	if err != nil {
		return SAMLClaims{}, err
	}
	if err := r.ParseForm(); err != nil {
		return SAMLClaims{}, fmt.Errorf("invalid saml form")
	}
	relay := r.PostForm.Get("RelayState")
	if relay == "" {
		relay = r.Form.Get("RelayState")
	}
	raw, err := rdb.GetDel(ctx, "saml:"+relay).Bytes()
	if err != nil {
		return SAMLClaims{}, fmt.Errorf("invalid or expired saml relay state")
	}
	var st samlRelayState
	if err := json.Unmarshal(raw, &st); err != nil || st.RequestID == "" {
		return SAMLClaims{}, fmt.Errorf("invalid saml relay state")
	}
	assertion, err := sp.ParseResponse(r, []string{st.RequestID})
	if err != nil {
		return SAMLClaims{}, fmt.Errorf("saml assertion: %w", err)
	}
	return mapSAMLClaims(cfg, assertion), nil
}

func mapSAMLClaims(cfg AuthSettings, a *saml.Assertion) SAMLClaims {
	attrs := map[string]string{}
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			name := attr.Name
			if name == "" {
				name = attr.FriendlyName
			}
			if len(attr.Values) > 0 {
				attrs[name] = attr.Values[0].Value
				if attr.FriendlyName != "" {
					attrs[attr.FriendlyName] = attr.Values[0].Value
				}
			}
		}
	}
	get := func(keys ...string) string {
		for _, k := range keys {
			if k == "" {
				continue
			}
			if v := strings.TrimSpace(attrs[k]); v != "" {
				return v
			}
		}
		return ""
	}

	username := get(cfg.SAMLAttrUsername, "uid", "username", "preferred_username", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
	email := get(cfg.SAMLAttrEmail, "email", "mail", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
	name := get(cfg.SAMLAttrDisplayName, "displayName", "cn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname")

	subject := ""
	if a.Subject != nil && a.Subject.NameID != nil {
		subject = strings.TrimSpace(a.Subject.NameID.Value)
	}
	if username == "" {
		username = subject
	}
	if email == "" && strings.Contains(subject, "@") {
		email = subject
	}
	username = sanitizeUsername(username)
	if email == "" {
		email = username + "@saml.local"
	}
	if name == "" {
		name = username
	}
	return SAMLClaims{
		Subject:  subject,
		Username: username,
		Email:    email,
		Name:     name,
	}
}

func SAMLErrorRedirect(base, msg string) string {
	base = strings.TrimRight(base, "/")
	return base + "/login?error=" + url.QueryEscape(msg)
}

func SAMLSuccessRedirect(base string) string {
	return strings.TrimRight(base, "/") + "/"
}
