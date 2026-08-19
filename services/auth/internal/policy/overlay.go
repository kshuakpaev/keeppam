package policy

import (
	"time"

	"github.com/google/uuid"
)

// aclConstraints is the WHEN/FROM/HOW/CONTEXT slice shared by bindings and named policies.
type aclConstraints struct {
	TimeStart           *time.Time
	TimeEnd             *time.Time
	DaysOfWeek          int
	RequiredTags        []string
	RequireTicket       bool
	RequireReason       bool
	AllowedCIDRs        []string
	AllowedCountries    []string
	AllowedDevices      []string
	AllowedNamespaces   []string
	AllowedEgress       []string
	CommandPolicyPackID *uuid.UUID
	SQLPolicyPackID     *uuid.UUID
	HTTPPolicyPackID    *uuid.UUID
	AppObjectPackID     *uuid.UUID
	MaxRisk             int
	RiskAction          string
	PIIAction           string
	FileTransfer        string
}

// overlayConstraints fills empty binding fields from a named Policy.
// Binding values win when set. require_ticket / require_reason are OR (policy can only tighten).
// days_of_week 127 (all days, the INSERT default) inherits the policy mask.
func overlayConstraints(base aclConstraints, pol aclConstraints, hasPolicy bool) aclConstraints {
	if !hasPolicy {
		return base
	}
	out := base
	if out.TimeStart == nil {
		out.TimeStart = pol.TimeStart
	}
	if out.TimeEnd == nil {
		out.TimeEnd = pol.TimeEnd
	}
	if out.DaysOfWeek == 127 {
		out.DaysOfWeek = pol.DaysOfWeek
	}
	if len(out.RequiredTags) == 0 {
		out.RequiredTags = pol.RequiredTags
	}
	out.RequireTicket = out.RequireTicket || pol.RequireTicket
	out.RequireReason = out.RequireReason || pol.RequireReason
	if len(out.AllowedCIDRs) == 0 {
		out.AllowedCIDRs = pol.AllowedCIDRs
	}
	if len(out.AllowedCountries) == 0 {
		out.AllowedCountries = pol.AllowedCountries
	}
	if len(out.AllowedDevices) == 0 {
		out.AllowedDevices = pol.AllowedDevices
	}
	if len(out.AllowedNamespaces) == 0 {
		out.AllowedNamespaces = pol.AllowedNamespaces
	}
	if len(out.AllowedEgress) == 0 {
		out.AllowedEgress = pol.AllowedEgress
	}
	if out.CommandPolicyPackID == nil {
		out.CommandPolicyPackID = pol.CommandPolicyPackID
	}
	if out.SQLPolicyPackID == nil {
		out.SQLPolicyPackID = pol.SQLPolicyPackID
	}
	if out.HTTPPolicyPackID == nil {
		out.HTTPPolicyPackID = pol.HTTPPolicyPackID
	}
	if out.AppObjectPackID == nil {
		out.AppObjectPackID = pol.AppObjectPackID
	}
	if out.MaxRisk == 0 {
		out.MaxRisk = pol.MaxRisk
		if pol.RiskAction != "" {
			out.RiskAction = pol.RiskAction
		}
	}
	if out.PIIAction == "" {
		out.PIIAction = pol.PIIAction
	}
	if out.FileTransfer == "" {
		out.FileTransfer = pol.FileTransfer
	}
	return out
}

func inheritStr(b, p *string) *string {
	if b != nil && *b != "" {
		return b
	}
	if p != nil && *p != "" {
		return p
	}
	return nil
}
