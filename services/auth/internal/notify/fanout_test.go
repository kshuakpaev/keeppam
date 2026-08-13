package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/policy"
)

func TestFilterRecipients(t *testing.T) {
	a := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	b := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	c := uuid.MustParse("00000000-0000-0000-0000-000000000003")
	got := FilterRecipients([]uuid.UUID{a, b, a, uuid.Nil, c}, b)
	if len(got) != 2 || got[0] != a || got[1] != c {
		t.Fatalf("got %v", got)
	}
	if n := FilterRecipients([]uuid.UUID{b}, b); len(n) != 0 {
		t.Fatalf("self-only should be empty: %v", n)
	}
	if n := FilterRecipients(nil, a); len(n) != 0 {
		t.Fatalf("empty %v", n)
	}
}

func TestJITPayloadNoSecrets(t *testing.T) {
	aid := uuid.MustParse("00000000-0000-0000-0000-0000000000aa")
	req := policy.AccessRequest{
		ID: aid, AssetID: uuid.MustParse("00000000-0000-0000-0000-0000000000bb"),
		RequesterID: uuid.MustParse("00000000-0000-0000-0000-0000000000cc"),
		Reason: "need root", TicketID: "INC-1", DurationMinutes: 30,
		Status: "pending", AssetName: "prod-db", RequesterUsername: "alice",
	}
	p := JITPayload("jit.created", req)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ToLower(string(raw))
	for _, bad := range []string{"password", "secret", "token", "kubeconfig"} {
		if strings.Contains(s, bad) {
			t.Fatalf("payload leaked %s: %s", bad, s)
		}
	}
	if p["event"] != "jit.created" || p["source"] != "keeppam" {
		t.Fatalf("meta %+v", p)
	}
	if p["ticket_id"] != "INC-1" || p["duration_minutes"] != 30 || p["id"] != aid.String() {
		t.Fatalf("fields %+v", p)
	}
}
