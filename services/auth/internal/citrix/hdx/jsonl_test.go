package hdx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	evs := []RecordingEvt{
		{T: "2026-01-01T00:00:00Z", Event: "hdx_ocr", Seq: 1, Meta: map[string]any{"text": "hi"}},
		{T: "2026-01-01T00:00:01Z", Event: "hdx_keystroke", Seq: 2, Meta: map[string]any{"line": "ls"}},
	}
	for _, e := range evs {
		if err := AppendJSONL(path, e); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ParseJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Event != "hdx_ocr" || got[1].Meta["line"] != "ls" {
		t.Fatalf("%#v", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestCallbackURL(t *testing.T) {
	if CallbackURL("http://pam:8080/") != "http://pam:8080/api/v1/citrix/hdx/ingest" {
		t.Fatal(CallbackURL("http://pam:8080/"))
	}
	if CallbackURL("") != "" {
		t.Fatal("empty")
	}
}
