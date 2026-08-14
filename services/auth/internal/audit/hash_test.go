package audit

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/store"
)

func TestHashStableAndRoundtrip(t *testing.T) {
	id := uuid.MustParse("01900000-0000-7000-8000-0000000000aa")
	ts := time.Date(2026, 8, 14, 12, 0, 0, 123456789, time.UTC)
	actor := uuid.MustParse("01900000-0000-7000-8000-0000000000bb")
	p := map[string]any{"reason": "need", "n": 30}
	h1 := Hash("", id, ts, &actor, "jit.created", "asset", "x", p)
	h2 := Hash("", id, ts.Add(time.Nanosecond), &actor, "jit.created", "asset", "x", map[string]any{"n": 30, "reason": "need"})
	if h1 != h2 {
		t.Fatalf("key order / nano should not change hash\n%s\n%s", h1, h2)
	}
	e := store.AuditEvent{
		ID: id, TS: ts, ActorID: &actor, Action: "jit.created",
		ResourceType: "asset", ResourceID: "x", Payload: p, PrevHash: "", Hash: h1,
	}
	if HashEvent(e) != h1 {
		t.Fatal("HashEvent mismatch")
	}
}

func TestCheckEventsOKAndBreak(t *testing.T) {
	a := uuid.MustParse("01900000-0000-7000-8000-000000000001")
	b := uuid.MustParse("01900000-0000-7000-8000-000000000002")
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	e1 := store.AuditEvent{ID: a, TS: ts, Action: "a", Payload: map[string]any{}}
	e1.Hash = HashEvent(e1)
	e2 := store.AuditEvent{ID: b, TS: ts.Add(time.Second), Action: "b", PrevHash: e1.Hash, Payload: map[string]any{"ok": true}}
	e2.Hash = HashEvent(e2)
	got := CheckEvents([]store.AuditEvent{e1, e2})
	if !got.OK || got.Events != 2 || got.DigestOK != 2 || got.DigestMismatch != 0 {
		t.Fatalf("%+v", got)
	}
	if got.HeadHash != e1.Hash || got.TailHash != e2.Hash {
		t.Fatalf("head/tail %+v", got)
	}

	broken := e2
	broken.PrevHash = "dead"
	got = CheckEvents([]store.AuditEvent{e1, broken})
	if got.OK || len(got.Breaks) != 1 || got.Breaks[0].Reason != "bad_prev" {
		t.Fatalf("break %+v", got)
	}

	first := e1
	first.PrevHash = "x"
	got = CheckEvents([]store.AuditEvent{first})
	if got.OK || got.Breaks[0].Reason != "first_prev" {
		t.Fatalf("first %+v", got)
	}

	empty := CheckEvents(nil)
	if !empty.OK || empty.Events != 0 {
		t.Fatalf("empty %+v", empty)
	}
}

func TestBatchMAC(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	env, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatal(err)
	}
	a := BatchMAC(env, "", "f", "l", 3, "h1", "h2")
	b := BatchMAC(env, "", "f", "l", 3, "h1", "h2")
	if a == "" || a != b {
		t.Fatalf("stable %q %q", a, b)
	}
	if BatchMAC(env, "x", "f", "l", 3, "h1", "h2") == a {
		t.Fatal("prev mac should change")
	}
	if BatchMAC(nil, "", "f", "l", 3, "h1", "h2") != "" {
		t.Fatal("nil envelope")
	}
}
