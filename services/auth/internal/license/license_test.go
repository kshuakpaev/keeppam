package license

import (
	"testing"
	"time"
)

func TestEvaluateSoftHard(t *testing.T) {
	f := File{MaxAssets: 100, SoftWarnPct: 90, Issued: "2026-01-01"}
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
	f := File{MaxAssets: 100, SoftWarnPct: 90, Expires: "2020-01-01"}
	if !f.IsExpired(time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("expected expired")
	}
	st := f.Evaluate(0, time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC))
	if !st.HardBlocked {
		t.Fatal(st)
	}
}
