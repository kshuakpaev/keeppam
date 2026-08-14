package obs

import "testing"

func TestParseAlertmanagerWebhook(t *testing.T) {
	raw := []byte(`{
	  "status": "firing",
	  "alerts": [{
	    "status": "firing",
	    "labels": {"alertname": "KeepPAMAPIDown", "severity": "critical"},
	    "annotations": {"summary": "API scrape is down", "description": "api:8080"},
	    "startsAt": "2026-08-14T15:00:00Z",
	    "fingerprint": "abc123"
	  }]
	}`)
	ev, err := ParseAlertmanagerWebhook(raw)
	if err != nil || len(ev) != 1 {
		t.Fatalf("%v %+v", err, ev)
	}
	if ev[0].Name != "KeepPAMAPIDown" || ev[0].Status != "firing" || ev[0].Fingerprint != "abc123" {
		t.Fatalf("%+v", ev[0])
	}
	if ev[0].Summary != "API scrape is down" {
		t.Fatal(ev[0].Summary)
	}
}

func TestParseAlertmanagerWebhookEmpty(t *testing.T) {
	_, err := ParseAlertmanagerWebhook([]byte(`{"status":"firing","alerts":[]}`))
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = ParseAlertmanagerWebhook([]byte(`not-json`))
	if err == nil {
		t.Fatal("expected error")
	}
}
