package settings

import "testing"

func TestOAuthReady(t *testing.T) {
	cfg := AuthSettings{
		Mode: "oauth", PublicBaseURL: "http://pam.local",
		OAuthAuthorizeURL: "http://idp/auth", OAuthTokenURL: "http://idp/token",
		OAuthUserinfoURL: "http://idp/me", OIDCClientID: "c", HasOIDCSecret: true,
	}
	if !OAuthReady(cfg) {
		t.Fatal("want ready")
	}
	cfg.OAuthUserinfoURL = ""
	if OAuthReady(cfg) {
		t.Fatal("userinfo required")
	}
}

func TestFirstClaimDigitalID(t *testing.T) {
	doc := map[string]any{"iin": "900101300123", "email": "a@example.kz", "name": "Almas"}
	if got := firstClaim(doc, "iin", "preferred_username"); got != "900101300123" {
		t.Fatal(got)
	}
	if got := firstClaim(doc, "missing", "email"); got != "a@example.kz" {
		t.Fatal(got)
	}
}

func TestOauthConfigCallback(t *testing.T) {
	cfg, err := oauthConfig(AuthSettings{
		PublicBaseURL:     "http://pam.example",
		OIDCClientID:      "cid",
		OAuthAuthorizeURL: "https://id.example/oauth/authorize",
		OAuthTokenURL:     "https://id.example/oauth/token",
		OIDCScopes:        "identification",
	}, "sec")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RedirectURL != "http://pam.example/api/v1/auth/oauth/callback" {
		t.Fatal(cfg.RedirectURL)
	}
	if cfg.Endpoint.AuthURL != "https://id.example/oauth/authorize" {
		t.Fatal(cfg.Endpoint.AuthURL)
	}
}
