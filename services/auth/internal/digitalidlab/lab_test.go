package digitalidlab

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestLoopbackAndPreset(t *testing.T) {
	if LoopbackAPI(":8080") != "http://127.0.0.1:8080" {
		t.Fatal(LoopbackAPI(":8080"))
	}
	p := MakePreset("http://pam.example", ":8080")
	if !strings.Contains(p.AuthorizeURL, "pam.example") || !strings.Contains(p.TokenURL, "127.0.0.1:8080") {
		t.Fatalf("%+v", p)
	}
	if p.ClientID != ClientID || p.UsernameClaim != "iin" {
		t.Fatal(p)
	}
}

func TestPKCERoundTrip(t *testing.T) {
	lab := &Lab{KV: NewMemKV()}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", lab.HandleAuthorize)
	mux.HandleFunc("/token", lab.HandleToken)
	mux.HandleFunc("/userinfo", lab.HandleUserinfo)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	verifier := oauth2.GenerateVerifier()
	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	form := url.Values{
		"client_id":             {ClientID},
		"redirect_uri":          {"http://pam.example/api/v1/auth/oauth/callback"},
		"state":                 {"st1"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"iin":                   {"900101300123"},
		"name":                  {"Almas"},
		"email":                 {"a@example.kz"},
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.PostForm(srv.URL+"/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || u.Query().Get("code") == "" {
		t.Fatalf("status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	code := u.Query().Get("code")

	tokForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://pam.example/api/v1/auth/oauth/callback"},
		"client_id":     {ClientID},
		"client_secret": {ClientSecret},
		"code_verifier": {verifier},
	}
	tokResp, err := http.PostForm(srv.URL+"/token", tokForm)
	if err != nil {
		t.Fatal(err)
	}
	defer tokResp.Body.Close()
	body, _ := io.ReadAll(tokResp.Body)
	if tokResp.StatusCode != 200 {
		t.Fatalf("token %d %s", tokResp.StatusCode, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		t.Fatal(string(body))
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	ui, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer ui.Body.Close()
	raw, _ := io.ReadAll(ui.Body)
	var doc map[string]string
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(string(raw))
	}
	if doc["iin"] != "900101300123" || doc["name"] != "Almas" {
		t.Fatal(doc)
	}
}
