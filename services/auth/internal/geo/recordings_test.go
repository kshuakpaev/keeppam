package geo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordingsSyncMode(t *testing.T) {
	if (&RecordingsConfig{RecordingsBackend: "s3", S3Bucket: "b"}).SyncMode() != "s3" {
		t.Fatal("s3 auto")
	}
	if (&RecordingsConfig{RsyncTarget: "host:/rec"}).SyncMode() != "rsync" {
		t.Fatal("rsync auto")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.cast"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	inv, err := ScanInventory(dir)
	if err != nil || inv.Files != 1 {
		t.Fatalf("%v %#v", err, inv)
	}
}

func TestPromotePlanStandby(t *testing.T) {
	st := Probe(context.Background(), Config{SiteID: "b", Role: RoleStandby, ReplicaDSN: ""})
	rec, _ := RecordingsStatusOf(RecordingsConfig{Mode: "rsync", LocalDir: t.TempDir(), RsyncTarget: "x:/y"}, nil)
	plan := BuildPromotePlan(Config{SiteID: "b", Role: RoleStandby}, rec, st)
	if plan.Role != RoleStandby || len(plan.Steps) < 4 {
		t.Fatalf("%#v", plan)
	}
}
