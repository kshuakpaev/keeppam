package crypto

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestEnvKeyProvider(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	p := EnvKeyProvider{RawB64: base64.StdEncoding.EncodeToString(raw)}
	got, err := p.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 || got[0] != 1 {
		t.Fatalf("bad key %#v", got)
	}
}

func TestFileKeyProvider(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 3)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key.b64")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := FileKeyProvider{Path: path}
	got, err := p.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("mismatch")
	}
}
