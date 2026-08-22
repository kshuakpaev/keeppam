package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	addr := ":8110"
	if v := os.Getenv("KEEPPAM_NAC_MOCK_ADDR"); v != "" {
		addr = v
	}
	http.HandleFunc("/keeppam/posture", handlePosture)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	log.Printf("nac-mock listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

type reqBody struct {
	Event    string `json:"event"`
	ClientIP string `json:"client_ip"`
	Reason   string `json:"reason"`
}

type respBody struct {
	Allowed bool   `json:"allowed"`
	VLAN    string `json:"vlan,omitempty"`
	Policy  string `json:"policy,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func handlePosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var req reqBody
	_ = json.NewDecoder(r.Body).Decode(&req)
	out := respBody{Allowed: true, VLAN: "vlan-pam", Policy: "keeppam-users"}
	if strings.HasSuffix(req.ClientIP, ".66") {
		out.Allowed = false
		out.Reason = "endpoint non-compliant (mock)"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
