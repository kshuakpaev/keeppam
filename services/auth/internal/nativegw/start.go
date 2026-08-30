package nativegw

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/auth"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/store"
)

// Starter opens a PAM session from a native client (no web portal).
type Starter struct {
	Auth     *auth.Service
	Assets   *assets.Service
	Policy   *policy.Service
	Sessions *sessionsvc.Service
}

// SplitLogin parses "user+ASSET" or "user+ASSET/account" (same as SSH :2222).
func SplitLogin(user string) (login, hint string) {
	user = strings.TrimSpace(user)
	if i := strings.IndexByte(user, '+'); i >= 0 {
		return user[:i], strings.TrimSpace(user[i+1:])
	}
	return user, ""
}

func (s *Starter) Authenticate(ctx context.Context, login, password, ip string) (store.User, error) {
	if s == nil || s.Auth == nil {
		return store.User{}, fmt.Errorf("auth not configured")
	}
	return s.Auth.AuthenticatePassword(ctx, login, password, ip)
}

// Start creates a pending session for protocol after ACL/owner Evaluate.
// hint is asset name or asset/account (from login suffix or client database name).
func (s *Starter) Start(ctx context.Context, user store.User, protocol, hint, ip string) (sessionsvc.Session, assets.TargetCreds, error) {
	if s == nil || s.Assets == nil || s.Policy == nil || s.Sessions == nil {
		return sessionsvc.Session{}, assets.TargetCreds{}, fmt.Errorf("native gateway not configured")
	}
	if !rbac.HasPermission(user.Permissions, "sessions.connect") {
		return sessionsvc.Session{}, assets.TargetCreds{}, fmt.Errorf("access denied")
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	hint = strings.TrimSpace(hint)
	if hint == "" {
		return sessionsvc.Session{}, assets.TargetCreds{}, fmt.Errorf("asset required: use user+ASSET or user+ASSET/account")
	}
	targets, err := s.listTargets(ctx, user, protocol)
	if err != nil {
		return sessionsvc.Session{}, assets.TargetCreds{}, err
	}
	chosen, err := resolveTarget(targets, hint)
	if err != nil {
		return sessionsvc.Session{}, assets.TargetCreds{}, err
	}
	bypass := rbac.HasPermission(user.Permissions, "users.write")
	ev, err := s.Policy.Evaluate(ctx, policy.AccessCheck{
		UserID: user.ID, AssetID: chosen.AssetID, RoleNames: user.Roles, Bypass: bypass,
		Now: time.Now(), ClientIP: ip, IgnoreTicket: true,
	})
	if err != nil {
		return sessionsvc.Session{}, assets.TargetCreds{}, err
	}
	if !ev.OK {
		return sessionsvc.Session{}, assets.TargetCreds{}, fmt.Errorf("access denied")
	}
	frozen := s.Policy.Freeze(ctx, ev, false, bypass)
	sess, err := s.Sessions.Create(ctx, user.ID, sessionsvc.CreateInput{
		AssetID: chosen.AssetID, AccountID: chosen.AccountID, Protocol: protocol, ClientIP: ip,
		RiskScore: ev.RiskScore, RiskFactors: ev.RiskFactors,
		AccessPolicyID: ev.AccessPolicyID, SQLPolicyPackID: ev.SQLPolicyPackID,
		HTTPPolicyPackID: ev.HTTPPolicyPackID, AppObjectPackID: ev.AppObjectPackID,
		PolicySnapshot: &frozen,
	}, "native-gateway")
	if err != nil {
		return sessionsvc.Session{}, assets.TargetCreds{}, err
	}
	creds, err := s.Assets.GetTargetCreds(ctx, chosen.AssetID, chosen.AccountID)
	if err != nil {
		_ = s.Sessions.MarkEnded(ctx, sess.ID, err.Error())
		return sessionsvc.Session{}, assets.TargetCreds{}, err
	}
	return sess, creds, nil
}

type targetRef struct {
	AssetID     uuid.UUID
	AccountID   uuid.UUID
	AssetName   string
	AccountName string
}

func (s *Starter) listTargets(ctx context.Context, user store.User, protocol string) ([]targetRef, error) {
	bypass := rbac.HasPermission(user.Permissions, "users.write")
	list, err := s.Assets.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []targetRef
	now := time.Now()
	for _, a := range list {
		if !strings.EqualFold(a.Protocol, protocol) || a.Status != "active" {
			continue
		}
		ok, err := s.Policy.Allowed(ctx, policy.AccessCheck{
			UserID: user.ID, AssetID: a.ID, RoleNames: user.Roles, Bypass: bypass, Now: now, IgnoreTicket: true, SkipRisk: true,
		})
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		full, err := s.Assets.Get(ctx, a.ID)
		if err != nil {
			continue
		}
		for _, acc := range full.Accounts {
			if acc.Status != "active" || !acc.HasSecret {
				continue
			}
			out = append(out, targetRef{
				AssetID: a.ID, AccountID: acc.ID, AssetName: a.Name, AccountName: acc.Username,
			})
		}
	}
	return out, nil
}

func resolveTarget(targets []targetRef, cmd string) (*targetRef, error) {
	cmd = strings.TrimSpace(cmd)
	assetName := cmd
	accountName := ""
	if i := strings.IndexByte(cmd, '/'); i >= 0 {
		assetName = cmd[:i]
		accountName = cmd[i+1:]
	}
	var matches []targetRef
	for _, t := range targets {
		if !strings.EqualFold(t.AssetName, assetName) {
			continue
		}
		if accountName == "" || strings.EqualFold(t.AccountName, accountName) {
			matches = append(matches, t)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("target not found or denied: %s", cmd)
	}
	if len(matches) > 1 && accountName == "" {
		return nil, fmt.Errorf("ambiguous asset %s — use asset/account", assetName)
	}
	t := matches[0]
	return &t, nil
}
