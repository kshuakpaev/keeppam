package appaccess

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/store"
)

var ErrNotFound = errors.New("not found")

type Service struct {
	db     *store.DB
	aud    *audit.Service
	env    *crypto.Envelope
	assets *assets.Service
	policy *policy.Service
	rdb    *redis.Client
}

func New(db *store.DB, aud *audit.Service, env *crypto.Envelope, assetsSvc *assets.Service, pol *policy.Service, rdb *redis.Client) *Service {
	return &Service{db: db, aud: aud, env: env, assets: assetsSvc, policy: pol, rdb: rdb}
}

type Integration struct {
	AssetID              uuid.UUID `json:"asset_id"`
	AuthMode             string    `json:"auth_mode"`
	LoginURL             string    `json:"login_url"`
	OIDCIssuer           string    `json:"oidc_issuer"`
	OIDCClientID         string    `json:"oidc_client_id"`
	HasOIDCClientSecret  bool      `json:"has_oidc_client_secret"`
	RecordingMode        string    `json:"recording_mode"`
	HeaderName           string    `json:"header_name"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type UpsertInput struct {
	AuthMode            string `json:"auth_mode"`
	LoginURL            string `json:"login_url"`
	OIDCIssuer          string `json:"oidc_issuer"`
	OIDCClientID        string `json:"oidc_client_id"`
	OIDCClientSecret    string `json:"oidc_client_secret"`
	ClearOIDCClientSecret bool `json:"clear_oidc_client_secret"`
	RecordingMode       string `json:"recording_mode"`
	HeaderName          string `json:"header_name"`
}

type Lease struct {
	ID             uuid.UUID `json:"id"`
	AssetID        uuid.UUID `json:"asset_id"`
	AccountID      uuid.UUID `json:"account_id"`
	UserID         uuid.UUID `json:"user_id"`
	Status         string    `json:"status"`
	ExpiresAt      time.Time `json:"expires_at"`
	CreatedAt      time.Time `json:"created_at"`
	Secret         string    `json:"secret,omitempty"`
	Username       string    `json:"username,omitempty"`
	LoginURL       string    `json:"login_url,omitempty"`
	AuthMode       string    `json:"auth_mode,omitempty"`
	AuthMethod     string    `json:"auth_method,omitempty"`
	OpenURL        string    `json:"open_url,omitempty"`
	Kind           string    `json:"kind,omitempty"` // app | k8s
	ClusterAddress string    `json:"cluster_address,omitempty"`
	ClusterPort    int       `json:"cluster_port,omitempty"`
}

func (s *Service) GetIntegration(ctx context.Context, assetID uuid.UUID) (Integration, error) {
	var in Integration
	var secret []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT asset_id, auth_mode, login_url, oidc_issuer, oidc_client_id, oidc_client_secret_enc,
			recording_mode, header_name, updated_at
		FROM app_integrations WHERE asset_id=$1`, assetID).Scan(
		&in.AssetID, &in.AuthMode, &in.LoginURL, &in.OIDCIssuer, &in.OIDCClientID, &secret,
		&in.RecordingMode, &in.HeaderName, &in.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Integration{
			AssetID: assetID, AuthMode: "vault_password", RecordingMode: "off",
		}, nil
	}
	if err != nil {
		return Integration{}, err
	}
	in.HasOIDCClientSecret = len(secret) > 0
	return in, nil
}

func (s *Service) UpsertIntegration(ctx context.Context, actorID, assetID uuid.UUID, in UpsertInput, ip, ua string) (Integration, error) {
	if in.AuthMode == "" {
		in.AuthMode = "vault_password"
	}
	switch in.AuthMode {
	case "oidc_broker", "vault_password", "header_inject":
	default:
		return Integration{}, fmt.Errorf("invalid auth_mode")
	}
	if in.RecordingMode == "" {
		in.RecordingMode = "off"
	}
	if in.RecordingMode != "off" && in.RecordingMode != "full" && in.RecordingMode != "isolated" {
		return Integration{}, fmt.Errorf("invalid recording_mode")
	}
	cur, _ := s.GetIntegration(ctx, assetID)
	var secretEnc []byte
	if in.ClearOIDCClientSecret {
		secretEnc = nil
	} else if strings.TrimSpace(in.OIDCClientSecret) != "" {
		b, err := s.env.Encrypt([]byte(in.OIDCClientSecret))
		if err != nil {
			return Integration{}, err
		}
		secretEnc = b
	} else {
		// keep existing
		_ = s.db.Pool.QueryRow(ctx, `SELECT oidc_client_secret_enc FROM app_integrations WHERE asset_id=$1`, assetID).Scan(&secretEnc)
	}
	if in.AuthMode == "" {
		in.AuthMode = cur.AuthMode
	}
	now := time.Now().UTC()
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO app_integrations (asset_id, auth_mode, login_url, oidc_issuer, oidc_client_id, oidc_client_secret_enc, recording_mode, header_name, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)
		ON CONFLICT (asset_id) DO UPDATE SET
			auth_mode=$2, login_url=$3, oidc_issuer=$4, oidc_client_id=$5,
			oidc_client_secret_enc=$6, recording_mode=$7, header_name=$8, updated_at=$9`,
		assetID, in.AuthMode, strings.TrimSpace(in.LoginURL), strings.TrimSpace(in.OIDCIssuer),
		strings.TrimSpace(in.OIDCClientID), secretEnc, in.RecordingMode, strings.TrimSpace(in.HeaderName), now)
	if err != nil {
		return Integration{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "app.integration.updated", "asset", assetID.String(), ip, ua, map[string]any{
		"auth_mode": in.AuthMode, "recording_mode": in.RecordingMode,
	})
	return s.GetIntegration(ctx, assetID)
}

func (s *Service) RequestAccess(ctx context.Context, userID, assetID, accountID uuid.UUID, roles []string, bypass bool, ticketID, reason, ip, ua string) (Lease, error) {
	integ, err := s.GetIntegration(ctx, assetID)
	if err != nil {
		return Lease{}, err
	}
	ev, err := s.policy.Evaluate(ctx, policy.AccessCheck{
		UserID: userID, AssetID: assetID, RoleNames: roles, Bypass: bypass, Now: time.Now(),
		TicketID: ticketID, Reason: reason, ClientIP: ip,
	})
	if err != nil {
		return Lease{}, err
	}
	if !ev.OK {
		payload := map[string]any{"reason": "policy"}
		if ev.DeniedByRisk {
			payload["reason"] = "risk"
			payload["risk_score"] = ev.RiskScore
			payload["risk_factors"] = ev.RiskFactors
			payload["max_risk"] = ev.MaxRisk
			payload["risk_action"] = ev.RiskAction
		}
		_ = s.aud.Record(ctx, &userID, "app.access.denied", "asset", assetID.String(), ip, ua, payload)
		return Lease{}, fmt.Errorf("%s", ev.DenyMessage())
	}

	switch integ.AuthMode {
	case "oidc_broker":
		return s.beginOIDC(ctx, userID, assetID, integ, ip, ua)
	case "header_inject", "vault_password":
		return s.createLease(ctx, userID, assetID, accountID, integ, ip, ua)
	default:
		return s.createLease(ctx, userID, assetID, accountID, integ, ip, ua)
	}
}

// RequestK8sAccess issues a short-lived kubeconfig/SA token lease for a k8s asset.
func (s *Service) RequestK8sAccess(ctx context.Context, userID, assetID, accountID uuid.UUID, roles []string, bypass bool, ticketID, reason, ip, ua string) (Lease, error) {
	asset, err := s.assets.Get(ctx, assetID)
	if err != nil {
		return Lease{}, err
	}
	if asset.AssetType != "k8s" && asset.Protocol != "kubectl" {
		return Lease{}, fmt.Errorf("asset is not a kubernetes cluster (asset_type=k8s or protocol=kubectl)")
	}
	if asset.Status != "active" {
		return Lease{}, fmt.Errorf("asset disabled")
	}
	ev, err := s.policy.Evaluate(ctx, policy.AccessCheck{
		UserID: userID, AssetID: assetID, RoleNames: roles, Bypass: bypass, Now: time.Now(),
		TicketID: ticketID, Reason: reason, ClientIP: ip,
	})
	if err != nil {
		return Lease{}, err
	}
	if !ev.OK {
		payload := map[string]any{"reason": "policy", "ticket_id": ticketID}
		if ev.DeniedByRisk {
			payload["reason"] = "risk"
			payload["risk_score"] = ev.RiskScore
			payload["risk_factors"] = ev.RiskFactors
			payload["max_risk"] = ev.MaxRisk
			payload["risk_action"] = ev.RiskAction
		}
		_ = s.aud.Record(ctx, &userID, "k8s.access.denied", "asset", assetID.String(), ip, ua, payload)
		return Lease{}, fmt.Errorf("%s", ev.DenyMessage())
	}
	if accountID == uuid.Nil {
		return Lease{}, fmt.Errorf("account_id required")
	}
	creds, err := s.assets.GetTargetCreds(ctx, assetID, accountID)
	if err != nil {
		return Lease{}, err
	}
	if strings.TrimSpace(creds.Secret) == "" {
		return Lease{}, fmt.Errorf("account has no kubeconfig/token secret")
	}
	id := store.NewID()
	now := time.Now().UTC()
	exp := now.Add(15 * time.Minute)
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO credential_leases (id, asset_id, account_id, user_id, status, expires_at, created_at)
		VALUES ($1,$2,$3,$4,'active',$5,$6)`, id, assetID, accountID, userID, exp, now)
	if err != nil {
		return Lease{}, err
	}
	_ = s.aud.Record(ctx, &userID, "k8s.access.granted", "asset", assetID.String(), ip, ua, map[string]any{
		"lease_id": id.String(), "account_id": accountID.String(), "auth_method": creds.AuthMethod,
		"username": creds.Account.Username, "ticket_id": ticketID,
	})
	apiURL := fmt.Sprintf("https://%s", asset.Address)
	if asset.Port > 0 && asset.Port != 443 {
		apiURL = fmt.Sprintf("https://%s:%d", asset.Address, asset.Port)
	}
	return Lease{
		ID: id, AssetID: assetID, AccountID: accountID, UserID: userID,
		Status: "active", ExpiresAt: exp, CreatedAt: now,
		Secret: creds.Secret, Username: creds.Account.Username,
		AuthMode: "vault_kubeconfig", AuthMethod: creds.AuthMethod,
		Kind: "k8s", ClusterAddress: asset.Address, ClusterPort: asset.Port,
		LoginURL: apiURL, OpenURL: apiURL,
	}, nil
}

func (s *Service) createLease(ctx context.Context, userID, assetID, accountID uuid.UUID, integ Integration, ip, ua string) (Lease, error) {
	if accountID == uuid.Nil {
		return Lease{}, fmt.Errorf("account_id required for vault_password / header_inject")
	}
	creds, err := s.assets.GetTargetCreds(ctx, assetID, accountID)
	if err != nil {
		return Lease{}, err
	}
	id := store.NewID()
	now := time.Now().UTC()
	exp := now.Add(15 * time.Minute)
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO credential_leases (id, asset_id, account_id, user_id, status, expires_at, created_at)
		VALUES ($1,$2,$3,$4,'active',$5,$6)`, id, assetID, accountID, userID, exp, now)
	if err != nil {
		return Lease{}, err
	}
	_ = s.aud.Record(ctx, &userID, "app.access.granted", "asset", assetID.String(), ip, ua, map[string]any{
		"lease_id": id.String(), "auth_mode": integ.AuthMode, "account_id": accountID.String(),
	})
	open := integ.LoginURL
	if open == "" {
		open = fmt.Sprintf("https://%s", creds.Asset.Address)
		if creds.Asset.Port > 0 && creds.Asset.Port != 443 {
			open = fmt.Sprintf("https://%s:%d", creds.Asset.Address, creds.Asset.Port)
		}
	}
	return Lease{
		ID: id, AssetID: assetID, AccountID: accountID, UserID: userID,
		Status: "active", ExpiresAt: exp, CreatedAt: now,
		Secret: creds.Secret, Username: creds.Account.Username,
		LoginURL: open, AuthMode: integ.AuthMode, AuthMethod: creds.AuthMethod,
		OpenURL: open, Kind: "app",
	}, nil
}

func (s *Service) beginOIDC(ctx context.Context, userID, assetID uuid.UUID, integ Integration, ip, ua string) (Lease, error) {
	if integ.OIDCIssuer == "" || integ.OIDCClientID == "" {
		return Lease{}, fmt.Errorf("oidc_issuer and oidc_client_id required")
	}
	state := make([]byte, 16)
	_, _ = rand.Read(state)
	st := hex.EncodeToString(state)
	_ = s.rdb.Set(ctx, "keeppam:appoidc:"+st, fmt.Sprintf("%s|%s", userID.String(), assetID.String()), 10*time.Minute).Err()
	// Generic authorize URL (authorization_endpoint discovery skipped in MVP)
	authURL := strings.TrimRight(integ.OIDCIssuer, "/") + "/authorize"
	u, err := url.Parse(authURL)
	if err != nil {
		return Lease{}, err
	}
	q := u.Query()
	q.Set("client_id", integ.OIDCClientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile")
	q.Set("state", st)
	if integ.LoginURL != "" {
		q.Set("redirect_uri", integ.LoginURL)
	}
	u.RawQuery = q.Encode()
	_ = s.aud.Record(ctx, &userID, "app.access.granted", "asset", assetID.String(), ip, ua, map[string]any{
		"auth_mode": "oidc_broker", "state": st,
	})
	return Lease{
		ID: store.NewID(), AssetID: assetID, UserID: userID, Status: "active",
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute), CreatedAt: time.Now().UTC(),
		AuthMode: "oidc_broker", OpenURL: u.String(), LoginURL: u.String(),
	}, nil
}

func (s *Service) ConsumeLease(ctx context.Context, userID, leaseID uuid.UUID) error {
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE credential_leases SET status='consumed', consumed_at=NOW()
		WHERE id=$1 AND user_id=$2 AND status='active' AND expires_at > NOW()`, leaseID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Service) NeedsFullRecording(ctx context.Context, assetID uuid.UUID) bool {
	in, err := s.GetIntegration(ctx, assetID)
	return err == nil && in.RecordingMode == "full"
}

func (s *Service) IsIsolated(ctx context.Context, assetID uuid.UUID) bool {
	in, err := s.GetIntegration(ctx, assetID)
	return err == nil && in.RecordingMode == "isolated"
}

func (s *Service) NeedsHTTPSSession(ctx context.Context, assetID uuid.UUID) bool {
	in, err := s.GetIntegration(ctx, assetID)
	return err == nil && (in.RecordingMode == "full" || in.RecordingMode == "isolated")
}
