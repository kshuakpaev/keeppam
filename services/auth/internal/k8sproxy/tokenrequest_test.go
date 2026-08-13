package k8sproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/keeppam/auth/internal/assets"
)

func TestResolveSA(t *testing.T) {
	ns, name := ResolveSA(assets.Account{Username: "deployer"})
	if ns != "default" || name != "deployer" {
		t.Fatalf("got ns=%s name=%s", ns, name)
	}
	ns, name = ResolveSA(assets.Account{
		Username:       "label",
		K8sSANamespace: " kube-system ",
		K8sSAName:      " keeppam ",
	})
	if ns != "kube-system" || name != "keeppam" {
		t.Fatalf("got ns=%s name=%s", ns, name)
	}
}

func TestClampTokenTTL(t *testing.T) {
	if ClampTokenTTL(0) != 15*time.Minute {
		t.Fatal("default 900s")
	}
	if ClampTokenTTL(10) != time.Minute {
		t.Fatal("min 60s")
	}
	if ClampTokenTTL(200000) != 24*time.Hour {
		t.Fatal("max 24h")
	}
	if ClampTokenTTL(120) != 2*time.Minute {
		t.Fatal("passthrough")
	}
}

func TestRequestTokenOK(t *testing.T) {
	exp := time.Now().UTC().Add(12 * time.Minute).Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/namespaces/apps/serviceaccounts/ci/token" {
			t.Fatalf("path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer vault-sa" {
			t.Fatalf("auth %s", got)
		}
		var body struct {
			Spec struct {
				ExpirationSeconds int64 `json:"expirationSeconds"`
			} `json:"spec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Spec.ExpirationSeconds != 900 {
			t.Fatalf("ttl %d", body.Spec.ExpirationSeconds)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiVersion": "authentication.k8s.io/v1",
			"kind":       "TokenRequest",
			"status": map[string]any{
				"token":               "ephemeral.jwt",
				"expirationTimestamp": exp.Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	up := &Upstream{Server: u, Token: "vault-sa"}
	tr, err := RequestToken(context.Background(), up, TokenRequestSpec{
		Namespace: "apps", Name: "ci", TTL: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Token != "ephemeral.jwt" {
		t.Fatalf("token %q", tr.Token)
	}
	if tr.ExpiresAt.UTC().Truncate(time.Second) != exp {
		t.Fatalf("exp %s want %s", tr.ExpiresAt, exp)
	}
}

func TestRequestTokenForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"kind": "Status", "message": "forbidden: cannot create token", "reason": "Forbidden",
		})
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	up := &Upstream{Server: u, Token: "vault-sa"}
	_, err := RequestToken(context.Background(), up, TokenRequestSpec{Namespace: "ns", Name: "sa"})
	if err == nil || !strings.Contains(err.Error(), "cannot create token") {
		t.Fatalf("err=%v", err)
	}
}

func TestMintEphemeralDisabled(t *testing.T) {
	secret, mode, exp, meta, err := MintEphemeral(context.Background(), assets.TargetCreds{
		Secret:     "vault-plain",
		AuthMethod: "sa_token",
		Account:    assets.Account{TokenRequestEnabled: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret != "vault-plain" || mode != "vault_kubeconfig" || !exp.IsZero() || meta != nil {
		t.Fatalf("secret=%s mode=%s exp=%v meta=%v", secret, mode, exp, meta)
	}
}
