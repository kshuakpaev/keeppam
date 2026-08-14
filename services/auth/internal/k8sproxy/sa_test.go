package k8sproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
)

func TestDNS1123AndBindSAName(t *testing.T) {
	if DNS1123("Alice.Admin") != "alice-admin" {
		t.Fatal(DNS1123("Alice.Admin"))
	}
	ns, name := BindSAName(assets.Account{K8sBindUser: true, Username: "deployer"}, "Alice.Admin")
	if ns != "default" || name != "keeppam-alice-admin" {
		t.Fatalf("ns=%s name=%s", ns, name)
	}
	ns, name = BindSAName(assets.Account{K8sBindUser: true, K8sSAName: "team", K8sSANamespace: "apps"}, "bob")
	if ns != "apps" || name != "team-bob" {
		t.Fatalf("ns=%s name=%s", ns, name)
	}
	_, name = BindSAName(assets.Account{Username: "deployer"}, "alice")
	if name != "deployer" {
		t.Fatalf("unbound name %s", name)
	}
}

func TestEnsureSACreateAndBindToken(t *testing.T) {
	var gotBound map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/namespaces/default/serviceaccounts/keeppam-alice", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
	})
	mux.HandleFunc("/api/v1/namespaces/default/serviceaccounts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"kind": "ServiceAccount", "metadata": map[string]any{"name": "keeppam-alice", "uid": "sa-uid-1"},
		})
	})
	mux.HandleFunc("/api/v1/namespaces/default/serviceaccounts/keeppam-alice/token", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		spec, _ := body["spec"].(map[string]any)
		gotBound, _ = spec["boundObjectRef"].(map[string]any)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": map[string]any{"token": "bound.jwt", "expirationTimestamp": "2030-01-01T00:00:00Z"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	secret, mode, _, meta, err := MintEphemeral(context.Background(), assets.TargetCreds{
		AuthMethod: "sa_token",
		Secret:     "vault",
		Asset:      assets.Asset{Address: srv.URL},
		Account:    assets.Account{TokenRequestEnabled: true, K8sBindUser: true, TokenTTLSeconds: 120},
	}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if secret != "bound.jwt" || mode != "token_request" {
		t.Fatalf("secret=%s mode=%s", secret, mode)
	}
	if gotBound["uid"] != "sa-uid-1" || gotBound["kind"] != "ServiceAccount" {
		t.Fatalf("bound %#v", gotBound)
	}
	if meta["sa_name"] != "keeppam-alice" || meta["bind_user"] != true {
		t.Fatalf("meta %#v", meta)
	}
}

func TestEnsureBindSecretAndDelete(t *testing.T) {
	id := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	created := false
	deleted := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/namespaces/default/secrets/"+BindSecretName(id), func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			http.NotFound(w, r)
		case http.MethodDelete:
			deleted = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"kind":"Status","status":"Success"}`))
		default:
			http.Error(w, "method", 405)
		}
	})
	mux.HandleFunc("/api/v1/namespaces/default/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		created = true
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"kind": "Secret", "metadata": map[string]any{"name": BindSecretName(id), "uid": "sec-1"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	up := &Upstream{Server: u, Token: "vault"}
	uid, err := EnsureBindSecret(context.Background(), up, "default", BindSecretName(id), id.String())
	if err != nil || uid != "sec-1" || !created {
		t.Fatalf("uid=%s err=%v created=%v", uid, err, created)
	}
	if err := DeleteBindSecret(context.Background(), up, "default", BindSecretName(id)); err != nil || !deleted {
		t.Fatalf("del err=%v deleted=%v", err, deleted)
	}
}

func TestMintBindUserRequiresUsername(t *testing.T) {
	_, _, _, _, err := MintEphemeral(context.Background(), assets.TargetCreds{
		AuthMethod: "sa_token",
		Account:    assets.Account{TokenRequestEnabled: true, K8sBindUser: true},
	}, "")
	if err == nil || !strings.Contains(err.Error(), "PAM username") {
		t.Fatalf("err=%v", err)
	}
}
