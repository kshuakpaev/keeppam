package citrix

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildSTAQueryURL(t *testing.T) {
	u, err := buildSTAQueryURL("https://sta.example", "aabb")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "/Scripts/CtxSta.dll") || !strings.Contains(strings.ToUpper(u), "TICKET=AABB") {
		t.Fatal(u)
	}
}

func TestProbeExternalSTA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ticket") == "" {
			http.Error(w, "no", 400)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("OKTICKET\n"))
	}))
	defer srv.Close()
	ok, body, err := ProbeExternalSTA(context.Background(), srv.Client(), srv.URL, "ABC")
	if err != nil || !ok || !strings.Contains(body, "OKTICKET") {
		t.Fatalf("%v %v %q", ok, err, body)
	}
}

func TestParseResourcesJSON(t *testing.T) {
	raw := []byte(`{"resources":[{"id":"1","name":"Excel","launchurl":"https://sf/launch/1"}]}`)
	list, err := parseResourcesJSON(raw)
	if err != nil || len(list) != 1 || list[0].Name != "Excel" {
		t.Fatalf("%v %#v", err, list)
	}
}

func TestStoreFrontListResources(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "resources") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resources": []map[string]string{{"id": "a1", "name": "Notepad", "initialprogram": "#Notepad"}},
		})
	}))
	defer srv.Close()
	c := &StoreFrontClient{BaseURL: srv.URL, HTTP: srv.Client()}
	list, err := c.ListResources(context.Background())
	if err != nil || len(list) != 1 || list[0].Name != "Notepad" {
		t.Fatalf("%v %#v", err, list)
	}
}

func TestCtxStaSuccessBody(t *testing.T) {
	b := CtxStaSuccessBody("abcd", "sess")
	if !strings.Contains(b, "ABCD") || !strings.Contains(b, "sess") {
		t.Fatal(b)
	}
}
