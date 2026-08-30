package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

func OAuthReady(cfg AuthSettings) bool {
	return cfg.Mode == "oauth" &&
		strings.TrimSpace(cfg.PublicBaseURL) != "" &&
		strings.TrimSpace(cfg.OAuthAuthorizeURL) != "" &&
		strings.TrimSpace(cfg.OAuthTokenURL) != "" &&
		strings.TrimSpace(cfg.OAuthUserinfoURL) != "" &&
		strings.TrimSpace(cfg.OIDCClientID) != "" &&
		cfg.HasOIDCSecret
}

func oauthConfig(cfg AuthSettings, clientSecret string) (*oauth2.Config, error) {
	if strings.TrimSpace(cfg.PublicBaseURL) == "" {
		return nil, fmt.Errorf("public_base_url is required for OAuth")
	}
	authURL := strings.TrimSpace(cfg.OAuthAuthorizeURL)
	tokenURL := strings.TrimSpace(cfg.OAuthTokenURL)
	if authURL == "" || tokenURL == "" {
		return nil, fmt.Errorf("oauth_authorize_url and oauth_token_url required")
	}
	scopes := strings.Fields(cfg.OIDCScopes)
	return &oauth2.Config{
		ClientID:     strings.TrimSpace(cfg.OIDCClientID),
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		RedirectURL: strings.TrimRight(cfg.PublicBaseURL, "/") + "/api/v1/auth/oauth/callback",
		Scopes:      scopes,
	}, nil
}

func (s *Service) OAuthAuthCodeURL(ctx context.Context, rdb *redis.Client, cfg AuthSettings, clientSecret string) (string, error) {
	oauthCfg, err := oauthConfig(cfg, clientSecret)
	if err != nil {
		return "", err
	}
	verifier := oauth2.GenerateVerifier()
	state := randomToken(24)
	payload, _ := json.Marshal(oidcState{Verifier: verifier})
	if err := rdb.Set(ctx, "oauth:"+state, payload, 10*time.Minute).Err(); err != nil {
		return "", err
	}
	return oauthCfg.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(verifier),
	), nil
}

func (s *Service) OAuthExchange(ctx context.Context, rdb *redis.Client, cfg AuthSettings, clientSecret, code, state string) (OIDCClaims, error) {
	raw, err := rdb.GetDel(ctx, "oauth:"+state).Bytes()
	if err != nil {
		return OIDCClaims{}, fmt.Errorf("invalid or expired oauth state")
	}
	var st oidcState
	if err := json.Unmarshal(raw, &st); err != nil {
		return OIDCClaims{}, err
	}
	oauthCfg, err := oauthConfig(cfg, clientSecret)
	if err != nil {
		return OIDCClaims{}, err
	}
	tok, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return OIDCClaims{}, fmt.Errorf("oauth exchange: %w", err)
	}
	infoURL := strings.TrimSpace(cfg.OAuthUserinfoURL)
	if infoURL == "" {
		return OIDCClaims{}, fmt.Errorf("oauth_userinfo_url required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, infoURL, nil)
	if err != nil {
		return OIDCClaims{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return OIDCClaims{}, fmt.Errorf("oauth userinfo: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return OIDCClaims{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return OIDCClaims{}, fmt.Errorf("oauth userinfo status %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return OIDCClaims{}, fmt.Errorf("oauth userinfo json: %w", err)
	}
	username := firstClaim(doc, cfg.OAuthUsernameClaim, "iin", "preferred_username", "username", "sub", "phone", "mobile")
	email := firstClaim(doc, cfg.OAuthEmailClaim, "email", "mail")
	name := firstClaim(doc, cfg.OAuthNameClaim, "name", "display_name", "displayName", "fio")
	username = sanitizeUsername(username)
	if email == "" {
		email = username + "@oauth.local"
	}
	if name == "" {
		name = username
	}
	sub := firstClaim(doc, "sub", "id", "iin")
	return OIDCClaims{
		Subject:   sub,
		Email:     email,
		Preferred: username,
		Name:      name,
		Username:  username,
	}, nil
}

func firstClaim(doc map[string]any, keys ...string) string {
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v, ok := doc[k]
		if !ok {
			continue
		}
		s := strings.TrimSpace(fmt.Sprint(v))
		if s == "" || s == "<nil>" {
			continue
		}
		return s
	}
	return ""
}
