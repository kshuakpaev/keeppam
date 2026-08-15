package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type RiskInputs struct {
	Now              time.Time
	BreakGlass       bool
	FailedLogins24h  int
	ConcurrentActive int
	AnomBrute        bool
	AnomMulti        bool
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
	if score > 100 {
		score = 100
	}
	if factors == nil {
		factors = []string{}
	}
	return score, factors
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

func (s *Service) loadRiskInputs(ctx context.Context, userID, assetID uuid.UUID, now time.Time) (RiskInputs, error) {
	in := RiskInputs{Now: now}
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
	var nAssets int
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT asset_id) FROM sessions
		WHERE user_id=$1 AND created_at >= $2`, userID, from).Scan(&nAssets)
	in.AnomMulti = nAssets >= 4
	in.AnomBrute = in.FailedLogins24h >= 8
	return in, nil
}

func (s *Service) applyRisk(ctx context.Context, in AccessCheck, res *AccessResult, expires *time.Time) {
	if in.SkipRisk || in.Bypass || expires != nil {
		return
	}
	inputs, err := s.loadRiskInputs(ctx, in.UserID, in.AssetID, in.Now)
	if err != nil {
		return
	}
	res.RiskScore, res.RiskFactors = computeRisk(inputs)
	if res.MaxRisk > 0 && res.RiskScore > res.MaxRisk {
		res.OK = false
		res.DeniedByRisk = true
		if res.RiskAction == "" {
			res.RiskAction = "deny"
		}
	}
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
	inputs, err := s.loadRiskInputs(ctx, userID, assetID, now)
	if err != nil {
		return 0, []string{}
	}
	return computeRisk(inputs)
}
