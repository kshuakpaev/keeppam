package ai

import "testing"

func TestCatalogHidesExternalWhenDisallowed(t *testing.T) {
	onprem := Catalog(false)
	for _, p := range onprem {
		if p.NeedsKey || p.Mode == ModeExternal {
			t.Fatalf("external preset leaked: %+v", p)
		}
	}
	ext := Catalog(true)
	if len(ext) <= len(onprem) {
		t.Fatalf("expected extra free-tier presets, onprem=%d all=%d", len(onprem), len(ext))
	}
}

func TestMatchOllamaAndMock(t *testing.T) {
	if got := MatchPreset("mock://local", "mock", "mock", false); got != PresetMock {
		t.Fatalf("mock: %s", got)
	}
	if got := MatchPreset("http://ai-runtime:11434", "llama3.2", "nomic-embed-text", false); got != "ollama-llama32" {
		t.Fatalf("llama32: %s", got)
	}
	if got := MatchPreset("http://ai-runtime:11434", "qwen2.5", "", false); got != "ollama-qwen25" {
		t.Fatalf("qwen: %s", got)
	}
	if got := MatchEmbedPreset("http://ai-runtime:11434", "nomic-embed-text", false); got != "ollama-nomic" {
		t.Fatalf("embed: %s", got)
	}
}

func TestFindPreset(t *testing.T) {
	p := FindPreset("groq-llama33")
	if p == nil || !p.NeedsKey || p.Endpoint != DefaultGroqEndpoint {
		t.Fatalf("%+v", p)
	}
	if FindPreset("") != nil || FindPreset("nope") != nil {
		t.Fatal("expected nil")
	}
}

func TestRuntimeNameMatches(t *testing.T) {
	if !runtimeNameMatches("llama3.2:latest", "llama3.2") {
		t.Fatal("tag")
	}
	if runtimeNameMatches("mistral", "llama3.2") {
		t.Fatal("mismatch")
	}
}
