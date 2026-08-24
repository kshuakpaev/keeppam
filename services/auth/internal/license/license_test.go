package license

import (
	"testing"
	"time"
)

func TestEvaluateSoftHard(t *testing.T) {
	f := File{MaxAssets: 100, SoftWarnPct: 90, Issued: "2026-01-01", Source: "/var/lib/keeppam/license.lic"}
	st := f.Evaluate(89, time.Now())
	if st.SoftWarn || st.HardBlocked {
		t.Fatalf("%+v", st)
	}
	st = f.Evaluate(90, time.Now())
	if !st.SoftWarn || st.HardBlocked {
		t.Fatalf("soft %+v", st)
	}
	st = f.Evaluate(100, time.Now())
	if !st.HardBlocked {
		t.Fatalf("hard %+v", st)
	}
	if err := f.AllowCreate(100, time.Now()); err == nil {
		t.Fatal("expected deny")
	}
}

func TestExpired(t *testing.T) {
	f := File{MaxAssets: 100, SoftWarnPct: 90, Expires: "2020-01-01", Source: "/var/lib/keeppam/license.lic"}
	now := time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)
	if !f.IsExpired(now) {
		t.Fatal("expected expired")
	}
	if f.EffectiveMaxAssets(now) != ExpiredMaxAssets {
		t.Fatalf("want %d got %d", ExpiredMaxAssets, f.EffectiveMaxAssets(now))
	}
	st := f.Evaluate(0, now)
	if st.HardBlocked || !st.SoftWarn || st.MaxAssets != ExpiredMaxAssets {
		t.Fatalf("grace %+v", st)
	}
	if err := f.AllowCreate(4, now); err != nil {
		t.Fatal(err)
	}
	st = f.Evaluate(5, now)
	if !st.HardBlocked || st.MaxAssets != ExpiredMaxAssets {
		t.Fatalf("cap %+v", st)
	}
	if err := f.AllowCreate(5, now); err == nil {
		t.Fatal("expected deny at grace cap")
	}
}

func TestVisibleLimit(t *testing.T) {
	valid := File{MaxAssets: 100, Expires: "2099-01-01", Source: "/var/lib/keeppam/license.lic"}
	if valid.VisibleLimit(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) != 0 {
		t.Fatal("valid license must not limit visibility")
	}
	expired := File{MaxAssets: 500, Expires: "2020-01-01", Source: "/x.lic"}
	if expired.VisibleLimit(time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)) != GraceMaxAssets {
		t.Fatal("expired must limit visibility")
	}
	unlic := DefaultFile()
	if !unlic.IsUnlicensed() || unlic.MaxAssets != GraceMaxAssets {
		t.Fatalf("default %+v", unlic)
	}
	if unlic.VisibleLimit(time.Now()) != GraceMaxAssets {
		t.Fatal("unlicensed must limit visibility")
	}
	st := unlic.Evaluate(0, time.Now())
	if st.HardBlocked || !st.SoftWarn || st.MaxAssets != GraceMaxAssets {
		t.Fatalf("unlicensed evaluate %+v", st)
	}
}
