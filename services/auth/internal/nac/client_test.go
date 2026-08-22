package nac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPostureURL(t *testing.T) {
	u, err := postureURL("https://nac.local", "generic")
	if err != nil || u != "https://nac.local/keeppam/posture" {
		t.Fatalf("%q %v", u, err)
	}
	_, err = postureURL("ftp://x", "generic")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCallPosture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keeppam/posture" {
			http.NotFound(w, r)
			return
		}
		var req PostureRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if strings.HasSuffix(req.ClientIP, ".66") {
			_ = json.NewEncoder(w).Encode(PostureResponse{Allowed: false, Reason: "non-compliant"})
			return
		}
		_ = json.NewEncoder(w).Encode(PostureResponse{Allowed: true, VLAN: "vlan10"})
	}))
	defer srv.Close()

	resp, err := callPosture(t.Context(), srv.URL, "tok", "generic", 0, PostureRequest{
		Event: "pre_connect", ClientIP: "10.0.0.1", Devices: []string{"TLS"},
	})
	if err != nil || !resp.Allowed || resp.VLAN != "vlan10" {
		t.Fatalf("got %+v err=%v", resp, err)
	}
	resp, err = callPosture(t.Context(), srv.URL, "", "generic", 0, PostureRequest{
		Event: "pre_connect", ClientIP: "10.0.0.66",
	})
	if err != nil || resp.Allowed {
		t.Fatalf("got %+v err=%v", resp, err)
	}
}

func TestNormalizeMode(t *testing.T) {
	if got, err := NormalizeMode(" ENFORCE "); err != nil || got != "enforce" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := NormalizeMode("drop"); err == nil {
		t.Fatal("expected error")
	}
}
