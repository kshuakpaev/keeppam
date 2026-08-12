package recstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalStore(t *testing.T) {
	dir := t.TempDir()
	st := &Local{Root: dir}
	path := filepath.Join(dir, "a.cast")
	if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if !st.Exists(context.Background(), path) {
		t.Fatal("expected exists")
	}
	if err := st.EnsureLocal(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if err := st.Sync(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if st.Backend() != "local" {
		t.Fatal(st.Backend())
	}
}
