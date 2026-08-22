package geo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteFenceStandby(t *testing.T) {
	err := WriteFenceError(context.Background(), Config{Role: RoleStandby, SiteID: "b"}, WitnessConfig{}, nil)
	if err == nil {
		t.Fatal("standby must fence")
	}
}

func TestWriteFenceSplitBrainPeer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/geoz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"site_id":"site-b","role":"primary","allows_writes":true}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := Config{SiteID: "site-a", Role: RolePrimary, PeerURL: srv.URL + "/geoz"}
	ws := EvaluateWitness(context.Background(), cfg, WitnessConfig{Mode: "peer"}, nil)
	if !ws.SplitBrain {
		t.Fatalf("%#v", ws)
	}
	err := WriteFenceError(context.Background(), cfg, WitnessConfig{Mode: "peer"}, nil)
	if err == nil {
		t.Fatal("expected fence")
	}
}
