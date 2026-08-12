package itsm

import "testing"

func TestMockTicket(t *testing.T) {
	open := mockTicket("DEMO-100")
	if open.Status != "Open" {
		t.Fatalf("want Open, got %q", open.Status)
	}
	closed := mockTicket("DEMO-CLOSED")
	if closed.Status != "Closed" {
		t.Fatalf("want Closed, got %q", closed.Status)
	}
	if statusAllowed(closed.Status, []string{"Open", "In Progress"}) {
		t.Fatal("closed should not be allowed")
	}
	if !statusAllowed("In Progress", []string{"Open", "in progress"}) {
		t.Fatal("case-insensitive match expected")
	}
}

func TestLookupJSON(t *testing.T) {
	raw := map[string]any{
		"fields": map[string]any{
			"status": map[string]any{"name": "To Do"},
			"summary": "fix",
		},
	}
	if got := lookupJSON(raw, "fields.status.name"); got != "To Do" {
		t.Fatalf("got %q", got)
	}
	arr := map[string]any{"result": []any{map[string]any{"state": "2"}}}
	if got := lookupJSON(arr, "result.0.state"); got != "2" {
		t.Fatalf("got %q", got)
	}
}
