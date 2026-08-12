package recstore

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	if st.ObjectLockMode() != "" {
		t.Fatal("local lock")
	}
	deleted, worm, err := st.TryDelete(context.Background(), path)
	if err != nil || worm || !deleted {
		t.Fatalf("delete: del=%v worm=%v err=%v", deleted, worm, err)
	}
}

func TestObjectLockHeadersInSign(t *testing.T) {
	s3 := &S3{
		Endpoint: "http://localhost:9000", Region: "us-east-1", Bucket: "b",
		AccessKey: "AKIA", SecretKey: "secret", PathStyle: true,
		LockMode: "COMPLIANCE", LockDays: 30,
	}
	body := []byte("hello")
	req, err := http.NewRequest(http.MethodPut, s3.objectURL("rec/a.cast"), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Amz-Object-Lock-Mode", "COMPLIANCE")
	req.Header.Set("X-Amz-Object-Lock-Retain-Until-Date", "2030-01-01T00:00:00.000Z")
	if err := s3.sign(req, body); err != nil {
		t.Fatal(err)
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "x-amz-object-lock-mode") {
		t.Fatalf("lock mode not signed: %s", auth)
	}
	if !strings.Contains(auth, "x-amz-object-lock-retain-until-date") {
		t.Fatalf("retain date not signed: %s", auth)
	}
}

