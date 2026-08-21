package policy

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOverlayEmptyBindingTakesPolicy(t *testing.T) {
	start := time.Date(2000, 1, 1, 9, 0, 0, 0, time.UTC)
	end := time.Date(2000, 1, 1, 18, 0, 0, 0, time.UTC)
	pack := uuid.MustParse("01900000-0000-7000-8000-000000000060")
	pol := aclConstraints{
		TimeStart:           &start,
		TimeEnd:             &end,
		DaysOfWeek:          62,
		RequiredTags:        []string{"prod"},
		RequireTicket:       true,
		AllowedCIDRs:        []string{"10.0.0.0/8"},
		AllowedCountries:    []string{"LAN"},
		AllowedDevices:      []string{"WEBAUTHN"},
		AllowedNamespaces:   []string{"prod"},
		AllowedEgress:       []string{"10.1.2.0/24:5432"},
		CommandPolicyPackID: &pack,
		MaxRisk:             40,
		RiskAction:          "require_approval",
		PIIAction:           "mask",
		FileTransfer:        "capture",
	}
	out := overlayConstraints(aclConstraints{DaysOfWeek: 127, RiskAction: "deny"}, pol, true)
	if out.TimeStart == nil || !out.TimeStart.Equal(start) {
		t.Fatal("time_start")
	}
	if out.DaysOfWeek != 62 {
		t.Fatalf("days=%d", out.DaysOfWeek)
	}
	if !out.RequireTicket {
		t.Fatal("ticket")
	}
	if len(out.AllowedCIDRs) != 1 || out.CommandPolicyPackID == nil || out.MaxRisk != 40 || out.RiskAction != "require_approval" || out.PIIAction != "mask" || out.FileTransfer != "capture" {
		t.Fatalf("%+v", out)
	}
}

func TestOverlayBindingWins(t *testing.T) {
	polPack := uuid.MustParse("01900000-0000-7000-8000-000000000060")
	bindPack := uuid.MustParse("01900000-0000-7000-8000-000000000061")
	start := time.Date(2000, 1, 1, 9, 0, 0, 0, time.UTC)
	bindStart := time.Date(2000, 1, 1, 10, 0, 0, 0, time.UTC)
	pol := aclConstraints{
		TimeStart:           &start,
		DaysOfWeek:          62,
		AllowedCIDRs:        []string{"10.0.0.0/8"},
		CommandPolicyPackID: &polPack,
		MaxRisk:             40,
		RiskAction:          "deny",
	}
	base := aclConstraints{
		TimeStart:           &bindStart,
		DaysOfWeek:          127,
		AllowedCIDRs:        []string{"192.168.0.0/16"},
		CommandPolicyPackID: &bindPack,
		MaxRisk:             20,
		RiskAction:          "require_approval",
	}
	out := overlayConstraints(base, pol, true)
	if !out.TimeStart.Equal(bindStart) {
		t.Fatal("binding time")
	}
	if out.DaysOfWeek != 62 {
		t.Fatal("127 should inherit policy days")
	}
	if out.AllowedCIDRs[0] != "192.168.0.0/16" {
		t.Fatal("binding cidr")
	}
	if *out.CommandPolicyPackID != bindPack {
		t.Fatal("binding pack")
	}
	if out.MaxRisk != 20 || out.RiskAction != "require_approval" {
		t.Fatal("binding risk")
	}
}

func TestOverlayNoPolicy(t *testing.T) {
	base := aclConstraints{DaysOfWeek: 127, MaxRisk: 0}
	out := overlayConstraints(base, aclConstraints{DaysOfWeek: 62, MaxRisk: 40}, false)
	if out.DaysOfWeek != 127 || out.MaxRisk != 0 {
		t.Fatalf("%+v", out)
	}
}

func TestOverlayTicketOR(t *testing.T) {
	out := overlayConstraints(
		aclConstraints{DaysOfWeek: 1, RequireTicket: false, RequireReason: true},
		aclConstraints{RequireTicket: true, RequireReason: false},
		true,
	)
	if !out.RequireTicket || !out.RequireReason {
		t.Fatal("OR tighten")
	}
}
