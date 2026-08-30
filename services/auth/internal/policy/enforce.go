package policy

import (
	"context"
)

func (s *Service) enforceDenied(ctx context.Context, in AccessCheck, res AccessResult) {
	if s == nil || s.onBreach == nil || !res.DeniedByRisk || !IsHardRiskAction(res.RiskAction) {
		return
	}
	s.onBreach(ctx, in.UserID, in.SessionID, in.AssetID, res.RiskAction, res.RiskScore, in.ClientIP)
}
