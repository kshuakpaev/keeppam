package sbom

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFromRuntime(t *testing.T) {
	bom := FromRuntime()
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.5" {
		t.Fatalf("%+v", bom)
	}
	if bom.Metadata.Component == nil || bom.Metadata.Component.Name == "" {
		t.Fatal("main component")
	}
	if len(bom.Components) == 0 {
		t.Fatal("expected stdlib or deps")
	}
}

func TestFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.json")
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"example"}]}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEEPPAM_SBOM_FILE", path)
	bom, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(bom.Components) != 1 || bom.Components[0].Name != "example" {
		t.Fatalf("%+v", bom)
	}
	t.Setenv("KEEPPAM_SBOM_FILE", "")
	rt, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if rt.Metadata.Component == nil {
		t.Fatal("runtime fallback")
	}
}

func TestFromFileRejects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.json")
	if err := os.WriteFile(path, []byte(`{"bomFormat":"SPDX"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FromFile(path); err == nil {
		t.Fatal("expected error")
	}
}
