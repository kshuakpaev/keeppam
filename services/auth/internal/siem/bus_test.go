package siem

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/store"
)

func TestSplitBrokers(t *testing.T) {
	got := splitBrokers(" kafka:9092,  10.0.0.2:9092 , ")
	if len(got) != 2 || got[0] != "kafka:9092" || got[1] != "10.0.0.2:9092" {
		t.Fatalf("%v", got)
	}
	if len(splitBrokers("")) != 0 || len(splitBrokers(" , , ")) != 0 {
		t.Fatal("expected empty")
	}
}

func TestValidTransport(t *testing.T) {
	for _, tr := range []string{"off", "syslog_udp", "syslog_tcp", "webhook", "kafka", "nats", "opensearch"} {
		if !validTransport(tr) {
			t.Fatalf("want valid %s", tr)
		}
	}
	if validTransport("rabbit") {
		t.Fatal("rabbit")
	}
}

func TestEventECS(t *testing.T) {
	id := uuidMust()
	actor := id
	e := store.AuditEvent{
		ID: id, TS: time.Date(2026, 8, 17, 8, 0, 0, 0, time.UTC),
		ActorID: &actor, Action: "session.denied", ResourceType: "session", ResourceID: "abc",
		IP: "10.0.0.1", UserAgent: "ssh", Payload: map[string]any{"reason": "acl"},
		Hash: "deadbeef",
	}
	doc := EventECS(e)
	if doc["@timestamp"] != "2026-08-17T08:00:00Z" {
		t.Fatalf("ts %v", doc["@timestamp"])
	}
	ev := doc["event"].(map[string]any)
	if ev["dataset"] != "keeppam.audit" || ev["action"] != "session.denied" || ev["outcome"] != "failure" {
		t.Fatalf("event %+v", ev)
	}
	cats := ev["category"].([]string)
	if len(cats) != 1 || cats[0] != "session" {
		t.Fatalf("cat %v", cats)
	}
	if doc["source"].(map[string]any)["ip"] != "10.0.0.1" {
		t.Fatal("ip")
	}
}

func TestEncodeBulk(t *testing.T) {
	e := store.AuditEvent{
		ID: uuidMust(), TS: time.Date(2026, 8, 17, 8, 0, 0, 0, time.UTC),
		Action: "asset.acl.granted", ResourceType: "asset", ResourceID: "a1",
		Payload: map[string]any{},
	}
	raw := string(EncodeBulk("KeepPAM-Audit", []store.AuditEvent{e}))
	if !strings.Contains(raw, `"_index":"keeppam-audit"`) {
		t.Fatalf("index %s", raw)
	}
	if !strings.Contains(raw, `"dataset":"keeppam.audit"`) {
		t.Fatal("dataset")
	}
	if !strings.HasSuffix(raw, "\n") || strings.Count(raw, "\n") != 2 {
		t.Fatalf("ndjson lines %d %q", strings.Count(raw, "\n"), raw)
	}
}

func TestNormalizeIndexAndBulkURL(t *testing.T) {
	if NormalizeIndex("") != "keeppam-audit" || NormalizeIndex("!!!") != "keeppam-audit" {
		t.Fatal(NormalizeIndex(""), NormalizeIndex("!!!"))
	}
	if bulkURL("https://os:9200") != "https://os:9200/_bulk" {
		t.Fatal(bulkURL("https://os:9200"))
	}
	if bulkURL("https://os:9200/_bulk/") != "https://os:9200/_bulk" && bulkURL("https://os:9200/_bulk") != "https://os:9200/_bulk" {
		t.Fatal(bulkURL("https://os:9200/_bulk"))
	}
}

func TestFormatEventECS(t *testing.T) {
	got := formatEvent("ecs", store.AuditEvent{Action: "user.login.success", Payload: map[string]any{}})
	if !strings.Contains(got, `"dataset":"keeppam.audit"`) || !strings.Contains(got, `"outcome":"success"`) {
		t.Fatal(got)
	}
}

func TestFormatEventLEEF(t *testing.T) {
	id := uuidMust()
	actor := id
	got := formatEvent("leef", store.AuditEvent{
		ID: id, TS: time.Date(2026, 8, 29, 7, 0, 0, 0, time.UTC),
		ActorID: &actor, Action: "user.login.success", ResourceType: "user", ResourceID: "u1",
		IP: "10.1.2.3", Payload: map[string]any{"src": "oauth"}, Hash: "abc",
	})
	if !strings.HasPrefix(got, "LEEF:2.0|KeepPAM|KeepPAM|1.0|user.login.success|\t|") {
		t.Fatalf("prefix %q", got)
	}
	if !strings.Contains(got, "src=10.1.2.3") || !strings.Contains(got, "sev=3") {
		t.Fatal(got)
	}
}

func uuidMust() uuid.UUID {
	return uuid.MustParse("01900000-0000-7000-8000-000000000099")
}
