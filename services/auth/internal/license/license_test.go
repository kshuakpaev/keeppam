package license

import (
	"testing"
	"time"
)

func TestEvaluateSoftHard(t *testing.T) {
	f := File{MaxAssets: 100, SoftWarnPct: 90, Issued: "2026-01-01", Source: "/var/lib/keeppam/license.lic"}
	st := f.Evaluate(89, 0, time.Now())
	if st.SoftWarn || st.HardBlocked {
		t.Fatalf("%+v", st)
	}
	st = f.Evaluate(90, 0, time.Now())
	if !st.SoftWarn || st.HardBlocked {
		t.Fatalf("soft %+v", st)
	}
	st = f.Evaluate(100, 0, time.Now())
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
	st := f.Evaluate(0, 0, now)
	if st.HardBlocked || !st.SoftWarn || st.MaxAssets != ExpiredMaxAssets {
		t.Fatalf("grace %+v", st)
	}
	if err := f.AllowCreate(4, now); err != nil {
		t.Fatal(err)
	}
	st = f.Evaluate(5, 0, now)
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
	st := unlic.Evaluate(0, 0, time.Now())
	if st.HardBlocked || !st.SoftWarn || st.MaxAssets != GraceMaxAssets {
		t.Fatalf("unlicensed evaluate %+v", st)
	}
}

func TestUsersModelUnlimitedAssets(t *testing.T) {
	f := File{Model: ModelUsers, MaxUsers: 200, Source: "/var/lib/keeppam/license.lic"}
	normalizeFile(&f)
	now := time.Now()
	if f.ResolvedModel() != ModelUsers || f.MaxAssets != 0 {
		t.Fatalf("%+v", f)
	}
	if f.EffectiveMaxAssets(now) != 0 || f.VisibleLimit(now) != 0 {
		t.Fatal("users SKU must not cap assets")
	}
	if f.EffectiveMaxUsers(now) != 200 {
		t.Fatalf("max users %d", f.EffectiveMaxUsers(now))
	}
	if err := f.AllowCreate(999, now); err != nil {
		t.Fatal(err)
	}
	st := f.Evaluate(999, 199, now)
	if st.HardBlocked || st.LimitsAssets || !st.LimitsUsers {
		t.Fatalf("%+v", st)
	}
	if err := f.AllowSession(200, now); err == nil {
		t.Fatal("expected session deny")
	}
	if !IsCap(f.AllowSession(200, now)) {
		t.Fatal("expected CapError")
	}
}

func TestBothModel(t *testing.T) {
	f := File{MaxAssets: 10, MaxUsers: 3, Source: "/x.lic"}
	normalizeFile(&f)
	if f.Model != ModelBoth {
		t.Fatalf("model %s", f.Model)
	}
	now := time.Now()
	if err := f.AllowCreate(10, now); err == nil {
		t.Fatal("asset cap")
	}
	if err := f.AllowSession(3, now); err == nil {
		t.Fatal("session cap")
	}
	st := f.Evaluate(10, 3, now)
	if !st.HardBlockedAssets || !st.HardBlockedUsers {
		t.Fatalf("%+v", st)
	}
}

func TestInferLegacyJSON(t *testing.T) {
	f := File{MaxAssets: 100, Source: "/old.json"}
	normalizeFile(&f)
	if f.Model != ModelAssets || f.MaxUsers != 0 {
		t.Fatalf("%+v", f)
	}
}
