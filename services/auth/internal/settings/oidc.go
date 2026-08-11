package settings

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

type oidcState struct {
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
}

func (s *Service) OIDCAuthCodeURL(ctx context.Context, rdb *redis.Client, cfg AuthSettings, clientSecret string) (string, error) {
	if cfg.PublicBaseURL == "" {
		return "", fmt.Errorf("public_base_url is required for OIDC")
	}
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		return "", fmt.Errorf("oidc provider: %w", err)
	}
	scopes := strings.Fields(cfg.OIDCScopes)
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	oauthCfg := oauth2.Config{
		ClientID:     cfg.OIDCClientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.PublicBaseURL + "/api/v1/auth/oidc/callback",
		Scopes:       scopes,
	}
	verifier := oauth2.GenerateVerifier()
	state := randomToken(24)
	nonce := randomToken(16)
	payload, _ := json.Marshal(oidcState{Verifier: verifier, Nonce: nonce})
	if err := rdb.Set(ctx, "oidc:"+state, payload, 10*time.Minute).Err(); err != nil {
		return "", err
	}
	return oauthCfg.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(verifier),
		oidc.Nonce(nonce),
	), nil
}

type OIDCClaims struct {
	Subject     string
	Email       string
	Preferred   string
	Name        string
	Username    string
}

func (s *Service) OIDCExchange(ctx context.Context, rdb *redis.Client, cfg AuthSettings, clientSecret, code, state string) (OIDCClaims, error) {
	raw, err := rdb.GetDel(ctx, "oidc:"+state).Bytes()
	if err != nil {
		return OIDCClaims{}, fmt.Errorf("invalid or expired oidc state")
	}
	var st oidcState
	if err := json.Unmarshal(raw, &st); err != nil {
		return OIDCClaims{}, err
	}
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		return OIDCClaims{}, err
	}
	scopes := strings.Fields(cfg.OIDCScopes)
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	oauthCfg := oauth2.Config{
		ClientID:     cfg.OIDCClientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.PublicBaseURL + "/api/v1/auth/oidc/callback",
		Scopes:       scopes,
	}
	tok, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return OIDCClaims{}, fmt.Errorf("oidc exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return OIDCClaims{}, fmt.Errorf("no id_token in oidc response")
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID})
	idTok, err := verifier.Verify(ctx, rawID)
	if err != nil {
		return OIDCClaims{}, fmt.Errorf("id_token verify: %w", err)
	}
	var claims struct {
		Nonce             string `json:"nonce"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if err := idTok.Claims(&claims); err != nil {
		return OIDCClaims{}, err
	}
	if st.Nonce != "" && claims.Nonce != "" && claims.Nonce != st.Nonce {
		return OIDCClaims{}, fmt.Errorf("oidc nonce mismatch")
	}
	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = idTok.Subject
	}
	username = sanitizeUsername(username)
	email := claims.Email
	if email == "" {
		email = username + "@oidc.local"
	}
	name := claims.Name
	if name == "" {
		name = username
	}
	return OIDCClaims{
		Subject:   idTok.Subject,
		Email:     email,
		Preferred: claims.PreferredUsername,
		Name:      name,
		Username:  username,
	}, nil
}

func sanitizeUsername(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.Split(s, "@")[0]
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		out = "user"
	}
	return out
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Redirect helpers used by HTTP layer.
func OIDCErrorRedirect(base, msg string) string {
	base = strings.TrimRight(base, "/")
	return base + "/login?error=" + url.QueryEscape(msg)
}

func OIDCSuccessRedirect(base string) string {
	return strings.TrimRight(base, "/") + "/"
}
