package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/ueba"
)

var ErrStepUpRequired = errors.New("mfa_required")

type StepUpError struct {
	Result AccessResult
}

func (e *StepUpError) Error() string {
	if e == nil {
		return ErrStepUpRequired.Error()
	}
	return e.Result.RiskDenyMessage()
}

func (e *StepUpError) Unwrap() error { return ErrStepUpRequired }

type RiskInputs struct {
	Now              time.Time
	BreakGlass       bool
	FailedLogins24h  int
	ConcurrentActive int
	AnomBrute        bool
	AnomMulti        bool
	UnusualAsset     bool
	SpreadBurst      bool
	UEBABaseline     int
	NewIP            bool
	NewSubnet        bool
	ClientIP         string
}

func computeRisk(in RiskInputs) (score int, factors []string) {
	hour := in.Now.UTC().Hour()
	if hour < 6 {
		score += 25
		factors = append(factors, "off_hours")
	}
	if in.BreakGlass {
		score += 40
		factors = append(factors, "break_glass")
	}
	switch {
	case in.FailedLogins24h >= 8:
		score += 45
		factors = append(factors, "failed_logins")
	case in.FailedLogins24h >= 3:
		score += 30
		factors = append(factors, "failed_logins")
	case in.FailedLogins24h >= 1:
		score += 15
		factors = append(factors, "failed_logins")
	}
	switch {
	case in.ConcurrentActive >= 5:
		score += 20
		factors = append(factors, "concurrent")
	case in.ConcurrentActive >= 3:
		score += 10
		factors = append(factors, "concurrent")
	}
	if in.AnomBrute {
		score += 20
		factors = append(factors, "anom_brute")
	}
	if in.AnomMulti {
		score += 15
		factors = append(factors, "anom_multi")
	}
	if in.UnusualAsset {
		score += ueba.NewAssetPoints
		factors = append(factors, ueba.FactorNewAsset)
	}
	if in.SpreadBurst {
		score += ueba.SpreadPoints
		factors = append(factors, ueba.FactorSpread)
	}
	if in.NewSubnet {
		score += ueba.NewSubnetPoints
		factors = append(factors, ueba.FactorNewSubnet)
	} else if in.NewIP {
		score += ueba.NewIPPoints
		factors = append(factors, ueba.FactorNewIP)
	}
	if score > 100 {
		score = 100
	}
	if factors == nil {
		factors = []string{}
	}
	return score, factors
}

func NormalizeRiskAction(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		s = "deny"
	}
	if s != "deny" && s != "require_approval" && s != "require_mfa" && s != "terminate" && s != "lock_account" {
		return "", fmt.Errorf("risk_action must be deny, require_approval, require_mfa, terminate or lock_account")
	}
	return s, nil
}

func IsSSHOperation(op string) bool {
	return strings.HasPrefix(strings.TrimSpace(op), "ssh.")
}

func (r AccessResult) NeedsStepUp() bool {
	if !r.DeniedByRisk || r.RiskAction != "require_mfa" {
		return false
	}
	return !IsSSHOperation(r.Operation)
}

func decideRisk(res *AccessResult, stepUpVerified bool, operation string) {
	if res.MaxRisk <= 0 || res.RiskScore <= res.MaxRisk {
		return
	}
	if res.RiskAction == "require_mfa" && stepUpVerified && !IsSSHOperation(operation) {
		return
	}
	res.OK = false
	res.DeniedByRisk = true
	if res.RiskAction == "" {
		res.RiskAction = "deny"
	}
	if IsSSHOperation(operation) && res.RiskAction == "require_mfa" {
		res.RiskAction = "deny"
	}
}

func (r AccessResult) RiskDenyMessage() string {
	factors := strings.Join(r.RiskFactors, ",")
	if factors == "" {
		factors = "none"
	}
	msg := fmt.Sprintf("access denied by risk (score %d > %d, factors=%s)", r.RiskScore, r.MaxRisk, factors)
	if r.RiskAction == "require_approval" && r.Operation == "" {
		msg += "; create a JIT request"
	}
	if r.RiskAction == "require_approval" && r.Operation != "" {
		msg += "; command requires JIT approval"
	}
	if r.RiskAction == "require_mfa" {
		msg += "; complete step-up MFA"
	}
	if r.RiskAction == "terminate" {
		msg += "; session terminated by risk policy"
	}
	if r.RiskAction == "lock_account" {
		msg += "; account locked by risk policy"
	}
	return msg
}

func (r AccessResult) DenyMessage() string {
	if r.DeniedByOPA {
		if strings.TrimSpace(r.OPAReason) != "" {
			return "access denied by opa: " + r.OPAReason
		}
		return "access denied by opa"
	}
	if r.DeniedByRisk {
		return r.RiskDenyMessage()
	}
	return "access denied by policy"
}

func (r AccessResult) FillDenyPayload(payload map[string]any) {
	if payload == nil {
		return
	}
	if r.DeniedByOPA {
		payload["reason"] = "opa"
		if r.OPAReason != "" {
			payload["opa_reason"] = r.OPAReason
		}
		return
	}
	if r.DeniedByRisk {
		payload["reason"] = "risk"
		payload["risk_score"] = r.RiskScore
		payload["risk_factors"] = r.RiskFactors
		payload["max_risk"] = r.MaxRisk
		payload["risk_action"] = r.RiskAction
	}
}

func ReapplyRisk(res *AccessResult, stepUpVerified bool, operation string) {
	if res == nil {
		return
	}
	res.OK = true
	res.DeniedByRisk = false
	decideRisk(res, stepUpVerified, operation)
}

func IsHardRiskAction(action string) bool {
	return action == "terminate" || action == "lock_account"
}

func (s *Service) loadRiskInputs(ctx context.Context, userID, assetID uuid.UUID, now time.Time, clientIP string) (RiskInputs, error) {
	if now.IsZero() {
		now = time.Now()
	}
	in := RiskInputs{Now: now, ClientIP: strings.TrimSpace(clientIP)}
	if bg, err := s.HasActiveBreakGlass(ctx, userID, assetID); err == nil {
		in.BreakGlass = bg
	}
	var username string
	_ = s.db.Pool.QueryRow(ctx, `SELECT username FROM users WHERE id=$1`, userID).Scan(&username)
	from := now.UTC().Add(-24 * time.Hour)
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE action='user.login.failure' AND ts >= $1
		  AND (resource_id=$2 OR resource_id=$3 OR actor_id=$4)`,
		from, username, userID.String(), userID).Scan(&in.FailedLogins24h)
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions
		WHERE user_id=$1 AND status IN ('pending','active')`, userID).Scan(&in.ConcurrentActive)
	baselineFrom := ueba.BaselineFrom(now)
	var n24 int
	var seen24, seen30 bool
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT
			COUNT(DISTINCT asset_id) FILTER (WHERE created_at >= $2),
			COUNT(DISTINCT asset_id),
			COALESCE(BOOL_OR(asset_id = $3 AND created_at >= $2), false),
			COALESCE(BOOL_OR(asset_id = $3), false)
		FROM sessions
		WHERE user_id=$1 AND created_at >= $4 AND `+ueba.SessionSQL,
		userID, from, assetID, baselineFrom).Scan(&n24, &in.UEBABaseline, &seen24, &seen30)
	if assetID == uuid.Nil {
		seen24, seen30 = false, false
	}
	recent := n24
	if assetID != uuid.Nil && !seen24 {
		recent++
	}
	in.AnomMulti = recent >= 4
	in.AnomBrute = in.FailedLogins24h >= 8
	in.UnusualAsset = ueba.NewAsset(in.UEBABaseline, seen30)
	in.SpreadBurst = ueba.Spread(in.UEBABaseline, recent)
	in.NewIP, in.NewSubnet = s.sourceAnomaly(ctx, userID, baselineFrom, in.ClientIP)
	return in, nil
}

func (s *Service) sourceAnomaly(ctx context.Context, userID uuid.UUID, since time.Time, clientIP string) (newIP, newSubnet bool) {
	host, netKey, ok := ueba.ParseHostNet(clientIP)
	if !ok {
		return false, false
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT DISTINCT client_ip FROM sessions
		WHERE user_id=$1 AND created_at >= $2 AND COALESCE(client_ip,'') <> '' AND `+ueba.SessionSQL, userID, since)
	if err != nil {
		return false, false
	}
	defer rows.Close()
	hosts := map[string]struct{}{}
	nets := map[string]struct{}{}
	seenHost, seenNet := false, false
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return false, false
		}
		h, n, ok := ueba.ParseHostNet(raw)
		if !ok {
			continue
		}
		hosts[h] = struct{}{}
		nets[n] = struct{}{}
		if h == host {
			seenHost = true
		}
		if n == netKey {
			seenNet = true
		}
	}
	newSubnet = ueba.NewSubnet(len(nets), seenNet)
	newIP = ueba.NewIP(len(hosts), seenHost) && !newSubnet
	return newIP, newSubnet
}

func (s *Service) applyRisk(ctx context.Context, in AccessCheck, res *AccessResult, expires *time.Time) {
	if in.SkipRisk || in.Bypass || expires != nil {
		return
	}
	inputs, err := s.loadRiskInputs(ctx, in.UserID, in.AssetID, in.Now, in.ClientIP)
	if err != nil {
		return
	}
	res.RiskScore, res.RiskFactors = computeRisk(inputs)
	decideRisk(res, in.StepUpVerified, in.Operation)
	s.enforceDenied(ctx, in, *res)
	decision := "allow"
	if res.DeniedByRisk {
		decision = res.RiskAction
		if decision == "" {
			decision = "deny"
		}
	}
	payload := map[string]any{
		"score": res.RiskScore, "max_risk": res.MaxRisk, "action": res.RiskAction,
		"factors": res.RiskFactors, "decision": decision, "denied_by_risk": res.DeniedByRisk,
	}
	if inputs.UnusualAsset || inputs.SpreadBurst || inputs.NewIP || inputs.NewSubnet {
		payload["ueba_baseline"] = inputs.UEBABaseline
		payload["ueba_new_asset"] = inputs.UnusualAsset
		payload["ueba_spread"] = inputs.SpreadBurst
		payload["ueba_new_ip"] = inputs.NewIP
		payload["ueba_new_subnet"] = inputs.NewSubnet
	}
	if res.BindingID != nil {
		payload["binding_id"] = res.BindingID.String()
	}
	_ = s.aud.Record(ctx, &in.UserID, "access.risk.evaluated", "asset", in.AssetID.String(), in.ClientIP, "", payload)
}

func (s *Service) userRoleNames(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.name FROM user_role_bindings urb
		JOIN roles r ON r.id = urb.role_id
		WHERE urb.user_id=$1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Service) ScoreUser(ctx context.Context, userID, assetID uuid.UUID, now time.Time) (int, []string) {
	inputs, err := s.loadRiskInputs(ctx, userID, assetID, now, "")
	if err != nil {
		return 0, []string{}
	}
	return computeRisk(inputs)
}
