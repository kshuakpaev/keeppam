package auth

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/session"
	"github.com/keeppam/auth/internal/store"
)

// CertIdentities extracts candidate login keys from a client certificate:
// Subject CN, email SANs, then DNS SANs (lowercased, trimmed, unique).
func CertIdentities(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(raw string) {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	add(cert.Subject.CommonName)
	for _, e := range cert.EmailAddresses {
		add(e)
	}
	for _, d := range cert.DNSNames {
		add(d)
	}
	return out
}

// LoginCert maps a verified client certificate to a KeepPAM user and starts a session
// (or MFA challenge). Matching order per identity: users.x509_identity, then username, then email.
func (s *Service) LoginCert(ctx context.Context, cert *x509.Certificate, ip, ua string) (LoginResult, error) {
	ids := CertIdentities(cert)
	if len(ids) == 0 {
		_ = s.audit.Record(ctx, nil, "user.login.failure", "user", "", ip, ua, map[string]any{"reason": "x509_no_identity"})
		return LoginResult{}, fmt.Errorf("client certificate has no usable identity")
	}

	rlKey := session.RateKey(ip, "x509")
	fails, err := s.sessions.IncrLoginFail(ctx, rlKey, s.cfg.LockoutDuration)
	if err != nil {
		return LoginResult{}, err
	}
	if fails > int64(s.cfg.MaxFailedLogins*3) {
		_ = s.audit.Record(ctx, nil, "user.login.failure", "user", "", ip, ua, map[string]any{"reason": "rate_limited", "via": "x509"})
		return LoginResult{}, fmt.Errorf("too many attempts")
	}

	u, err := s.resolveCertUser(ctx, ids)
	if err != nil {
		_ = s.audit.Record(ctx, nil, "user.login.failure", "user", "", ip, ua, map[string]any{"reason": "x509_map", "error": err.Error()})
		return LoginResult{}, err
	}
	if u.Status == "disabled" {
		_ = s.audit.Record(ctx, &u.ID, "user.login.failure", "user", u.ID.String(), ip, ua, map[string]any{"reason": "disabled", "via": "x509"})
		return LoginResult{}, fmt.Errorf("account disabled")
	}
	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		_ = s.audit.Record(ctx, &u.ID, "user.login.failure", "user", u.ID.String(), ip, ua, map[string]any{"reason": "locked", "via": "x509"})
		return LoginResult{}, fmt.Errorf("account locked")
	}

	_ = s.sessions.ResetLoginFail(ctx, rlKey)
	return s.finishLogin(ctx, u, ip, ua, false, "x509")
}

func (s *Service) resolveCertUser(ctx context.Context, identities []string) (store.User, error) {
	byID := map[uuid.UUID]store.User{}
	add := func(u store.User) {
		byID[u.ID] = u
	}

	for _, id := range identities {
		u, err := s.db.GetUserByX509Identity(ctx, id)
		if err == nil {
			add(u)
			continue
		}
		if err != pgx.ErrNoRows {
			return store.User{}, err
		}
	}
	if len(byID) == 1 {
		for _, u := range byID {
			return u, nil
		}
	}
	if len(byID) > 1 {
		return store.User{}, fmt.Errorf("certificate matches multiple users")
	}

	for _, id := range identities {
		if u, err := s.db.GetUserByUsername(ctx, id); err == nil {
			add(u)
		} else if err != pgx.ErrNoRows {
			return store.User{}, err
		}
		if u, err := s.db.GetUserByEmail(ctx, id); err == nil {
			add(u)
		} else if err != pgx.ErrNoRows {
			return store.User{}, err
		}
	}
	switch len(byID) {
	case 0:
		return store.User{}, fmt.Errorf("certificate not mapped to a user")
	case 1:
		for _, u := range byID {
			return u, nil
		}
	}
	return store.User{}, fmt.Errorf("certificate matches multiple users")
}
