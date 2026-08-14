package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testDEK(t *testing.T) (raw []byte, b64 string) {
	t.Helper()
	raw = make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 7)
	}
	return raw, base64.StdEncoding.EncodeToString(raw)
}

func TestAWSKMSProvider(t *testing.T) {
	want, wantB64 := testDEK(t)
	var sawAuth, sawTarget bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if r.Header.Get("X-Amz-Target") == "TrentService.Decrypt" {
			sawTarget = true
		}
		if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			sawAuth = true
		}
		body, _ := io.ReadAll(r.Body)
		var in struct {
			CiphertextBlob string `json:"CiphertextBlob"`
			KeyID          string `json:"KeyId"`
		}
		_ = json.Unmarshal(body, &in)
		if in.CiphertextBlob != "cipher-blob" || in.KeyID != "alias/keeppam" {
			t.Errorf("body %#v", in)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"Plaintext":"` + wantB64 + `"}`))
	}))
	defer srv.Close()

	p := AWSKMSProvider{
		Region:     "eu-central-1",
		AccessKey:  "AKIAEXAMPLE",
		SecretKey:  "secret",
		Endpoint:   srv.URL,
		KeyID:      "alias/keeppam",
		Ciphertext: "cipher-blob",
	}
	got, err := p.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("dek mismatch")
	}
	if !sawAuth || !sawTarget {
		t.Fatalf("sigv4/target missing auth=%v target=%v", sawAuth, sawTarget)
	}
}

func TestGCPKMSProvider(t *testing.T) {
	want, wantB64 := testDEK(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ya29.test" {
			http.Error(w, "no token", 401)
			return
		}
		if !strings.HasSuffix(r.URL.Path, ":decrypt") {
			http.Error(w, "path "+r.URL.Path, 404)
			return
		}
		if !strings.Contains(r.URL.Path, "cryptoKeys/keeppam") {
			http.Error(w, "key "+r.URL.Path, 404)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"ciphertext":"gcp-ct"`) {
			http.Error(w, "ciphertext", 400)
			return
		}
		_, _ = w.Write([]byte(`{"plaintext":"` + wantB64 + `"}`))
	}))
	defer srv.Close()

	p := GCPKMSProvider{
		KeyName:     "projects/p/locations/global/keyRings/r/cryptoKeys/keeppam",
		AccessToken: "ya29.test",
		Endpoint:    srv.URL,
		Ciphertext:  "gcp-ct",
	}
	got, err := p.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("dek mismatch")
	}
}

func TestGCPKMSProviderMetadataToken(t *testing.T) {
	want, wantB64 := testDEK(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "flavor", 403)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"meta-tok","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/v1/projects/p/locations/global/keyRings/r/cryptoKeys/keeppam:decrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer meta-tok" {
			http.Error(w, "auth", 401)
			return
		}
		_, _ = w.Write([]byte(`{"plaintext":"` + wantB64 + `"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := GCPKMSProvider{
		KeyName:     "projects/p/locations/global/keyRings/r/cryptoKeys/keeppam",
		Endpoint:    srv.URL,
		MetadataURL: srv.URL + "/token",
		Ciphertext:  "x",
	}
	got, err := p.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("dek mismatch")
	}
}

func TestAzureKVProviderUnwrap(t *testing.T) {
	want, wantB64 := testDEK(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "csec" {
			http.Error(w, "creds", 401)
			return
		}
		if r.Form.Get("grant_type") != "client_credentials" {
			http.Error(w, "grant", 400)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"az-tok","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/keys/keeppam/unwrapkey", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer az-tok" {
			http.Error(w, "auth", 401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var in struct {
			Alg   string `json:"alg"`
			Value string `json:"value"`
		}
		_ = json.Unmarshal(body, &in)
		if in.Alg != "RSA-OAEP-256" || in.Value != "wrapped" {
			http.Error(w, "body", 400)
			return
		}
		_, _ = w.Write([]byte(`{"value":"` + wantB64 + `"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := AzureKVProvider{
		VaultURL:     srv.URL,
		KeyName:      "keeppam",
		TokenURL:     srv.URL + "/oauth2/v2.0/token",
		ClientID:     "cid",
		ClientSecret: "csec",
		Ciphertext:   "wrapped",
	}
	got, err := p.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("dek mismatch")
	}
}

func TestDecodeDEKRejectsShort(t *testing.T) {
	if _, err := decodeDEK(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("expected error")
	}
}
