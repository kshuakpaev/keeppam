package recarch

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNFSDestRoundTrip(t *testing.T) {
	root := t.TempDir()
	d, err := newNFSDest(root)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("KEEP-PAM-ARCHIVE")
	if err := d.Put(context.Background(), "sid/a.cast", bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if !d.Exists(context.Background(), "sid/a.cast") {
		t.Fatal("exists")
	}
	var buf bytes.Buffer
	if err := d.Get(context.Background(), "sid/a.cast", &buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), payload) {
		t.Fatalf("got %q", buf.Bytes())
	}
	src := filepath.Join(t.TempDir(), "a.cast")
	if err := os.WriteFile(src, payload, 0o640); err != nil {
		t.Fatal(err)
	}
	sum, err := fileSHA256(src)
	if err != nil || len(sum) != 64 {
		t.Fatalf("sha %s err %v", sum, err)
	}
}

func TestArchiveRelRejectsDotDot(t *testing.T) {
	if _, err := (&nfsDest{root: t.TempDir()}).abs("../x"); err == nil {
		t.Fatal("expected reject")
	}
}
