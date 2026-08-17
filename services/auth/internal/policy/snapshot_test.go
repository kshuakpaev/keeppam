package policy

import (
	"testing"

	"github.com/google/uuid"
)

func TestFromResultCopiesFields(t *testing.T) {
	id := uuid.MustParse("01900000-0000-7000-8000-000000000060")
	pol := uuid.MustParse("01900000-0000-7000-8000-000000000061")
	ev := AccessResult{
		OK: true, MaxRisk: 40, RiskAction: "require_mfa",
		HTTPPolicyPackID: &id, AccessPolicyID: &pol,
		TagACL: true, MatchTags: []string{"prod"}, AllowedNamespaces: []string{"kube-system"},
		AllowedEgress: []string{"10.1.2.0/24:5432"}, PIIAction: "mask",
	}
	sn := FromResult(ev)
	if sn.MaxRisk != 40 || sn.RiskAction != "require_mfa" || sn.HTTPPolicyPackID == nil || *sn.HTTPPolicyPackID != id {
		t.Fatalf("%+v", sn)
	}
	if sn.AccessPolicyID == nil || *sn.AccessPolicyID != pol || !sn.TagACL || len(sn.MatchTags) != 1 {
		t.Fatalf("%+v", sn)
	}
	got := sn.toResult()
	if !got.OK || got.MaxRisk != 40 || got.HTTPPolicyPackID == nil {
		t.Fatalf("%+v", got)
	}
	if sn.PIIAction != "mask" {
		t.Fatalf("pii %+v", sn.PIIAction)
	}
	if len(sn.AllowedEgress) != 1 || sn.AllowedEgress[0] != "10.1.2.0/24:5432" {
		t.Fatalf("egress %+v", sn.AllowedEgress)
	}
}

func TestCheckOpRiskSnapshotZeroMaxRisk(t *testing.T) {
	s := &Service{}
	ev, err := s.CheckOpRisk(nil, AccessCheck{
		Operation: "sql.drop",
		Snapshot:  &Snapshot{MaxRisk: 0, RiskAction: "deny"},
	})
	if err != nil || !ev.OK {
		t.Fatalf("frozen max_risk=0 must skip live Evaluate: %+v %v", ev, err)
	}
}
