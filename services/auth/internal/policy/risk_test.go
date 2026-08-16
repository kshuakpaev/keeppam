package policy

import (
	"strings"
	"testing"
	"time"
)

func TestComputeRiskEmpty(t *testing.T) {
	score, factors := computeRisk(RiskInputs{Now: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)})
	if score != 0 {
		t.Fatalf("score=%d want 0", score)
	}
	if len(factors) != 0 {
		t.Fatalf("factors=%v", factors)
	}
}

func TestComputeRiskOffHours(t *testing.T) {
	score, factors := computeRisk(RiskInputs{Now: time.Date(2026, 8, 13, 3, 0, 0, 0, time.UTC)})
	if score != 25 {
		t.Fatalf("score=%d want 25", score)
	}
	if len(factors) != 1 || factors[0] != "off_hours" {
		t.Fatalf("factors=%v", factors)
	}
}

func TestComputeRiskStackedCap(t *testing.T) {
	score, factors := computeRisk(RiskInputs{
		Now:              time.Date(2026, 8, 13, 2, 0, 0, 0, time.UTC),
		BreakGlass:       true,
		FailedLogins24h:  10,
		ConcurrentActive: 6,
		AnomBrute:        true,
		AnomMulti:        true,
	})
	// 25+40+45+20+20+15 = 165 → 100
	if score != 100 {
		t.Fatalf("score=%d want 100", score)
	}
	want := []string{"off_hours", "break_glass", "failed_logins", "concurrent", "anom_brute", "anom_multi"}
	if strings.Join(factors, ",") != strings.Join(want, ",") {
		t.Fatalf("factors=%v want %v", factors, want)
	}
}

func TestComputeRiskFailedLoginBuckets(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	s1, _ := computeRisk(RiskInputs{Now: now, FailedLogins24h: 1})
	s3, _ := computeRisk(RiskInputs{Now: now, FailedLogins24h: 3})
	s8, _ := computeRisk(RiskInputs{Now: now, FailedLogins24h: 8})
	if s1 != 15 || s3 != 30 || s8 != 45 {
		t.Fatalf("buckets %d %d %d", s1, s3, s8)
	}
}

func TestComputeRiskUEBA(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	score, factors := computeRisk(RiskInputs{Now: now, UnusualAsset: true})
	if score != 25 || len(factors) != 1 || factors[0] != "ueba_new_asset" {
		t.Fatalf("new asset score=%d factors=%v", score, factors)
	}
	score, factors = computeRisk(RiskInputs{Now: now, UnusualAsset: true, SpreadBurst: true, AnomMulti: true})
	if score != 60 {
		t.Fatalf("stacked ueba score=%d want 60", score)
	}
	want := "anom_multi,ueba_new_asset,ueba_spread"
	if strings.Join(factors, ",") != want {
		t.Fatalf("factors=%v want %s", factors, want)
	}
}

func TestRiskDenyMessage(t *testing.T) {
	r := AccessResult{DeniedByRisk: true, RiskScore: 72, MaxRisk: 40, RiskAction: "require_approval", RiskFactors: []string{"off_hours", "failed_logins"}}
	msg := r.DenyMessage()
	if !strings.Contains(msg, "score 72 > 40") || !strings.Contains(msg, "JIT") {
		t.Fatalf("msg=%s", msg)
	}
}

func TestNormalizeRiskAction(t *testing.T) {
	ok, err := NormalizeRiskAction("require_mfa")
	if err != nil || ok != "require_mfa" {
		t.Fatalf("got %s %v", ok, err)
	}
	if _, err := NormalizeRiskAction("explode"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecideRiskRequireMFA(t *testing.T) {
	res := AccessResult{OK: true, MaxRisk: 40, RiskScore: 72, RiskAction: "require_mfa"}
	decideRisk(&res, false, "")
	if res.OK || !res.DeniedByRisk || !res.NeedsStepUp() {
		t.Fatalf("want step-up, got ok=%v denied=%v action=%s", res.OK, res.DeniedByRisk, res.RiskAction)
	}
	res = AccessResult{OK: true, MaxRisk: 40, RiskScore: 72, RiskAction: "require_mfa"}
	decideRisk(&res, true, "")
	if !res.OK || res.DeniedByRisk {
		t.Fatal("step-up should allow connect")
	}
	res = AccessResult{OK: true, MaxRisk: 40, RiskScore: 72, RiskAction: "require_mfa"}
	decideRisk(&res, false, "sql.ddl")
	if res.OK || !res.NeedsStepUp() || res.RiskAction != "require_mfa" {
		t.Fatalf("sql should step-up: ok=%v action=%s needs=%v", res.OK, res.RiskAction, res.NeedsStepUp())
	}
	res = AccessResult{OK: true, MaxRisk: 40, RiskScore: 72, RiskAction: "require_mfa"}
	decideRisk(&res, true, "sql.ddl")
	if !res.OK || res.DeniedByRisk {
		t.Fatal("verified op step-up should allow SQL")
	}
	res = AccessResult{OK: true, MaxRisk: 40, RiskScore: 72, RiskAction: "require_mfa"}
	decideRisk(&res, true, "ssh.destructive")
	if res.OK || res.RiskAction != "deny" || res.NeedsStepUp() {
		t.Fatalf("SSH PTY stays deny: ok=%v action=%s needs=%v", res.OK, res.RiskAction, res.NeedsStepUp())
	}
}
