package assets

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"golang.org/x/crypto/ssh"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/store"
	"github.com/keeppam/auth/internal/tagpath"
)

type Service struct {
	db    *store.DB
	env   *crypto.Envelope
	aud   *audit.Service
	sshCA SSHCertIssuer
}

// SSHCertIssuer signs ephemeral user certificates when ssh_auth_mode=ssh_cert.
type SSHCertIssuer interface {
	Mode(ctx context.Context) string
	SignUser(ctx context.Context, principal string) (ssh.Signer, error)
}

func New(db *store.DB, env *crypto.Envelope, aud *audit.Service) *Service {
	return &Service{db: db, env: env, aud: aud}
}

func (s *Service) SetSSHCA(ca SSHCertIssuer) {
	s.sshCA = ca
}

type Asset struct {
	ID                 uuid.UUID  `json:"id"`
	Name               string     `json:"name"`
	AssetType          string     `json:"asset_type"`
	Hostname           string     `json:"hostname"`
	Address            string     `json:"address"`
	Port               int        `json:"port"`
	Protocol           string     `json:"protocol"`
	DatabaseName       string     `json:"database_name,omitempty"`
	Description        string     `json:"description"`
	Status             string     `json:"status"`
	Tags               []string   `json:"tags"`
	ApprovalStages     []string   `json:"approval_stages"`
	ApprovalMode       string     `json:"approval_mode"`
	QuorumN            int        `json:"quorum_n,omitempty"`
	QuorumM            int        `json:"quorum_m,omitempty"`
	ApproverGroupID    *uuid.UUID `json:"approver_group_id,omitempty"`
	ApproverGroupName  string     `json:"approver_group_name,omitempty"`
	HostKeyAlgo        string     `json:"host_key_algo,omitempty"`
	HostKeyFingerprint string     `json:"host_key_fingerprint,omitempty"`
	HostKeyLearnedAt   *time.Time `json:"host_key_learned_at,omitempty"`
	HostKeyBlob        []byte     `json:"-"`
	PamOnly            bool       `json:"pam_only"`
	FirewallAppliedAt  *time.Time `json:"firewall_applied_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	CreatedBy          *uuid.UUID `json:"created_by,omitempty"`
	Accounts           []Account  `json:"accounts,omitempty"`
}

type Account struct {
	ID                   uuid.UUID  `json:"id"`
	AssetID              uuid.UUID  `json:"asset_id"`
	Username             string     `json:"username"`
	AuthMethod           string     `json:"auth_method"`
	HasSecret            bool       `json:"has_secret"`
	Description          string     `json:"description"`
	Status               string     `json:"status"`
	LastRotatedAt        *time.Time `json:"last_rotated_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	CreatedBy            *uuid.UUID `json:"created_by,omitempty"`
	CheckoutUserID       *uuid.UUID `json:"checkout_user_id,omitempty"`
	CheckoutUsername     string     `json:"checkout_username,omitempty"`
	CheckoutAt           *time.Time `json:"checkout_at,omitempty"`
	CheckoutExpiresAt    *time.Time `json:"checkout_expires_at,omitempty"`
	CheckoutReason       string     `json:"checkout_reason,omitempty"`
	CheckedOut           bool       `json:"checked_out"`
	RotateAfterSession   bool       `json:"rotate_after_session"`
	RotateOnCheckin      bool       `json:"rotate_on_checkin"`
	RotateIntervalHours  int        `json:"rotate_interval_hours"`
	NextRotateAt         *time.Time `json:"next_rotate_at,omitempty"`
	DualControlCheckout  bool       `json:"dual_control_checkout"`
	TokenRequestEnabled  bool       `json:"token_request_enabled"`
	K8sSANamespace       string     `json:"k8s_sa_namespace"`
	K8sSAName            string     `json:"k8s_sa_name"`
	TokenTTLSeconds      int        `json:"token_ttl_seconds"`
	K8sImpersonate       bool       `json:"k8s_impersonate"`
	K8sImpersonatePrefix string     `json:"k8s_impersonate_prefix"`
	K8sBindUser          bool       `json:"k8s_bind_user"`
}

type CreateAssetInput struct {
	Name            string     `json:"name"`
	AssetType       string     `json:"asset_type"`
	Hostname        string     `json:"hostname"`
	Address         string     `json:"address"`
	Port            int        `json:"port"`
	Protocol        string     `json:"protocol"`
	DatabaseName    string     `json:"database_name"`
	Description     string     `json:"description"`
	Tags            []string   `json:"tags"`
	ApprovalStages  []string   `json:"approval_stages"`
	ApprovalMode    string     `json:"approval_mode"`
	QuorumN         int        `json:"quorum_n"`
	QuorumM         int        `json:"quorum_m"`
	ApproverGroupID *uuid.UUID `json:"approver_group_id"`
	PamOnly         *bool      `json:"pam_only"`
}

type UpdateAssetInput struct {
	Name            *string    `json:"name"`
	AssetType       *string    `json:"asset_type"`
	Hostname        *string    `json:"hostname"`
	Address         *string    `json:"address"`
	Port            *int       `json:"port"`
	Protocol        *string    `json:"protocol"`
	DatabaseName    *string    `json:"database_name"`
	Description     *string    `json:"description"`
	Status          *string    `json:"status"`
	Tags            *[]string  `json:"tags"`
	ApprovalStages  *[]string  `json:"approval_stages"`
	ApprovalMode    *string    `json:"approval_mode"`
	QuorumN         *int       `json:"quorum_n"`
	QuorumM         *int       `json:"quorum_m"`
	ApproverGroupID *uuid.UUID `json:"approver_group_id"`
	PamOnly         *bool      `json:"pam_only"`
}

type CreateAccountInput struct {
	Username             string `json:"username"`
	AuthMethod           string `json:"auth_method"`
	Secret               string `json:"secret"`
	Description          string `json:"description"`
	TokenRequestEnabled  bool   `json:"token_request_enabled"`
	K8sSANamespace       string `json:"k8s_sa_namespace"`
	K8sSAName            string `json:"k8s_sa_name"`
	TokenTTLSeconds      int    `json:"token_ttl_seconds"`
	K8sImpersonate       bool   `json:"k8s_impersonate"`
	K8sImpersonatePrefix string `json:"k8s_impersonate_prefix"`
	K8sBindUser          bool   `json:"k8s_bind_user"`
}

type UpdateAccountInput struct {
	Username             *string `json:"username"`
	AuthMethod           *string `json:"auth_method"`
	Secret               *string `json:"secret"`
	Description          *string `json:"description"`
	Status               *string `json:"status"`
	RotateAfterSession   *bool   `json:"rotate_after_session"`
	RotateOnCheckin      *bool   `json:"rotate_on_checkin"`
	RotateIntervalHours  *int    `json:"rotate_interval_hours"`
	DualControlCheckout  *bool   `json:"dual_control_checkout"`
	TokenRequestEnabled  *bool   `json:"token_request_enabled"`
	K8sSANamespace       *string `json:"k8s_sa_namespace"`
	K8sSAName            *string `json:"k8s_sa_name"`
	TokenTTLSeconds      *int    `json:"token_ttl_seconds"`
	K8sImpersonate       *bool   `json:"k8s_impersonate"`
	K8sImpersonatePrefix *string `json:"k8s_impersonate_prefix"`
	K8sBindUser          *bool   `json:"k8s_bind_user"`
}

func (s *Service) List(ctx context.Context) ([]Asset, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT a.id, a.name, a.asset_type, a.hostname, a.address, a.port, a.protocol, COALESCE(a.database_name,''), a.description, a.status,
			a.host_key_algo, a.host_key_blob, a.host_key_fp, a.host_key_learned_at,
			a.created_at, a.updated_at, a.created_by, COALESCE(a.approval_stages, '{manager}'), COALESCE(a.pam_only, TRUE), a.firewall_applied_at,
			COALESCE(a.approval_mode, 'sequential'), COALESCE(a.quorum_n, 1), COALESCE(a.quorum_m, 1), a.approver_group_id, COALESCE(g.name, '')
		FROM assets a
		LEFT JOIN groups g ON g.id = a.approver_group_id
		ORDER BY a.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		tags, err := s.tagsFor(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		a.Tags = tags
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (Asset, error) {
	row := s.db.Pool.QueryRow(ctx, `
		SELECT a.id, a.name, a.asset_type, a.hostname, a.address, a.port, a.protocol, COALESCE(a.database_name,''), a.description, a.status,
			a.host_key_algo, a.host_key_blob, a.host_key_fp, a.host_key_learned_at,
			a.created_at, a.updated_at, a.created_by, COALESCE(a.approval_stages, '{manager}'), COALESCE(a.pam_only, TRUE), a.firewall_applied_at,
			COALESCE(a.approval_mode, 'sequential'), COALESCE(a.quorum_n, 1), COALESCE(a.quorum_m, 1), a.approver_group_id, COALESCE(g.name, '')
		FROM assets a
		LEFT JOIN groups g ON g.id = a.approver_group_id
		WHERE a.id=$1`, id)
	a, err := scanAsset(row)
	if err != nil {
		return Asset{}, err
	}
	a.Tags, err = s.tagsFor(ctx, a.ID)
	if err != nil {
		return Asset{}, err
	}
	a.Accounts, err = s.listAccounts(ctx, a.ID)
	return a, err
}

func (s *Service) Create(ctx context.Context, actorID uuid.UUID, in CreateAssetInput, ip, ua string) (Asset, error) {
	if in.Name == "" || in.Address == "" {
		return Asset{}, fmt.Errorf("name and address required")
	}
	if in.AssetType == "" {
		in.AssetType = "host"
	}
	if in.Protocol == "" {
		in.Protocol = "ssh"
	}
	if in.Port <= 0 {
		in.Port = defaultPort(in.Protocol)
	}
	now := time.Now().UTC()
	dbName := strings.TrimSpace(in.DatabaseName)
	if dbName == "" && (in.Protocol == "postgres") {
		dbName = "postgres"
	}
	a := Asset{
		ID: store.NewID(), Name: in.Name, AssetType: in.AssetType,
		Hostname: in.Hostname, Address: in.Address, Port: in.Port,
		Protocol: in.Protocol, DatabaseName: dbName, Description: in.Description, Status: "active",
		Tags: in.Tags, ApprovalStages: assetApprovalStages(in.ApprovalStages), PamOnly: true, CreatedAt: now, UpdatedAt: now, CreatedBy: &actorID,
	}
	if err := applyAssetApproval(&a, in.ApprovalMode, in.ApprovalStages, in.QuorumN, in.QuorumM, in.ApproverGroupID); err != nil {
		return Asset{}, err
	}
	if in.PamOnly != nil {
		a.PamOnly = *in.PamOnly
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return Asset{}, err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `
		INSERT INTO assets (id, name, asset_type, hostname, address, port, protocol, database_name, description, status, created_at, updated_at, created_by, approval_stages, pam_only, approval_mode, quorum_n, quorum_m, approver_group_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		a.ID, a.Name, a.AssetType, a.Hostname, a.Address, a.Port, a.Protocol, a.DatabaseName, a.Description, a.Status, a.CreatedAt, a.UpdatedAt, a.CreatedBy, a.ApprovalStages, a.PamOnly, a.ApprovalMode, a.QuorumN, a.QuorumM, a.ApproverGroupID)
	if err != nil {
		return Asset{}, err
	}
	if err := setTagsTx(ctx, tx, a.ID, a.Tags); err != nil {
		return Asset{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Asset{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "asset.created", "asset", a.ID.String(), ip, ua, map[string]any{
		"name": a.Name, "address": a.Address, "protocol": a.Protocol,
	})
	return s.Get(ctx, a.ID)
}

func (s *Service) Update(ctx context.Context, actorID, id uuid.UUID, in UpdateAssetInput, ip, ua string) (Asset, error) {
	a, err := s.Get(ctx, id)
	if err != nil {
		return Asset{}, err
	}
	endpointChanged := false
	if in.Name != nil {
		a.Name = *in.Name
	}
	if in.AssetType != nil {
		a.AssetType = *in.AssetType
	}
	if in.Hostname != nil {
		a.Hostname = *in.Hostname
	}
	if in.Address != nil {
		if *in.Address != a.Address {
			endpointChanged = true
		}
		a.Address = *in.Address
	}
	if in.Port != nil {
		if *in.Port != a.Port {
			endpointChanged = true
		}
		a.Port = *in.Port
	}
	if in.Protocol != nil {
		a.Protocol = *in.Protocol
	}
	if in.DatabaseName != nil {
		a.DatabaseName = strings.TrimSpace(*in.DatabaseName)
	}
	if in.Description != nil {
		a.Description = *in.Description
	}
	if in.Status != nil {
		switch *in.Status {
		case "active", "disabled":
			a.Status = *in.Status
		default:
			return Asset{}, fmt.Errorf("invalid status")
		}
	}
	a.UpdatedAt = time.Now().UTC()
	if endpointChanged {
		a.HostKeyAlgo = ""
		a.HostKeyBlob = nil
		a.HostKeyFingerprint = ""
		a.HostKeyLearnedAt = nil
		a.FirewallAppliedAt = nil
	}
	if in.ApprovalMode != nil || in.QuorumN != nil || in.QuorumM != nil || in.ApprovalStages != nil {
		mode := a.ApprovalMode
		if in.ApprovalMode != nil {
			mode = *in.ApprovalMode
		}
		qn, qm := a.QuorumN, a.QuorumM
		if in.QuorumN != nil {
			qn = *in.QuorumN
		}
		if in.QuorumM != nil {
			qm = *in.QuorumM
		}
		stages := a.ApprovalStages
		if in.ApprovalStages != nil {
			stages = *in.ApprovalStages
		}
		gid := a.ApproverGroupID
		if in.ApprovalMode != nil {
			gid = in.ApproverGroupID
		}
		if err := applyAssetApproval(&a, mode, stages, qn, qm, gid); err != nil {
			return Asset{}, err
		}
	}
	if in.PamOnly != nil {
		a.PamOnly = *in.PamOnly
		if !a.PamOnly {
			a.FirewallAppliedAt = nil
		}
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return Asset{}, err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `
		UPDATE assets SET name=$2, asset_type=$3, hostname=$4, address=$5, port=$6,
			protocol=$7, database_name=$8, description=$9, status=$10, updated_at=$11,
			host_key_algo=$12, host_key_blob=$13, host_key_fp=$14, host_key_learned_at=$15,
			approval_stages=$16, pam_only=$17, firewall_applied_at=$18,
			firewall_probe_at=CASE WHEN $19 THEN NULL ELSE firewall_probe_at END,
			firewall_probe_reachable=CASE WHEN $19 THEN NULL ELSE firewall_probe_reachable END,
			approval_mode=$20, quorum_n=$21, quorum_m=$22, approver_group_id=$23
		WHERE id=$1`,
		a.ID, a.Name, a.AssetType, a.Hostname, a.Address, a.Port, a.Protocol, a.DatabaseName, a.Description, a.Status, a.UpdatedAt,
		a.HostKeyAlgo, a.HostKeyBlob, a.HostKeyFingerprint, a.HostKeyLearnedAt, a.ApprovalStages, a.PamOnly, a.FirewallAppliedAt, endpointChanged,
		a.ApprovalMode, a.QuorumN, a.QuorumM, a.ApproverGroupID)
	if err != nil {
		return Asset{}, err
	}
	if in.Tags != nil {
		if err := setTagsTx(ctx, tx, a.ID, *in.Tags); err != nil {
			return Asset{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Asset{}, err
	}
	action := "asset.updated"
	if in.Status != nil && *in.Status == "disabled" {
		action = "asset.disabled"
	}
	payload := map[string]any{"name": a.Name, "status": a.Status}
	if endpointChanged {
		payload["host_key_cleared"] = true
	}
	_ = s.aud.Record(ctx, &actorID, action, "asset", id.String(), ip, ua, payload)
	return s.Get(ctx, id)
}

func (s *Service) Delete(ctx context.Context, actorID, id uuid.UUID, ip, ua string) error {
	a, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	_, err = s.db.Pool.Exec(ctx, `DELETE FROM assets WHERE id=$1`, id)
	if err != nil {
		return err
	}
	return s.aud.Record(ctx, &actorID, "asset.deleted", "asset", id.String(), ip, ua, map[string]any{"name": a.Name})
}

func (s *Service) CreateAccount(ctx context.Context, actorID, assetID uuid.UUID, in CreateAccountInput, ip, ua string) (Account, error) {
	if _, err := s.Get(ctx, assetID); err != nil {
		return Account{}, err
	}
	if in.Username == "" {
		return Account{}, fmt.Errorf("username required")
	}
	if in.AuthMethod == "" {
		in.AuthMethod = "password"
	}
	switch in.AuthMethod {
	case "password", "ssh_key", "kubeconfig", "sa_token":
	default:
		return Account{}, fmt.Errorf("invalid auth_method")
	}
	var secretEnc []byte
	if in.Secret != "" {
		enc, err := s.env.Encrypt([]byte(in.Secret))
		if err != nil {
			return Account{}, err
		}
		secretEnc = enc
	}
	ttl, err := normalizeTokenTTL(in.TokenTTLSeconds)
	if err != nil {
		return Account{}, err
	}
	if err := requireBindUserTokenRequest(in.K8sBindUser, in.TokenRequestEnabled); err != nil {
		return Account{}, err
	}
	now := time.Now().UTC()
	id := store.NewID()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO asset_accounts (id, asset_id, username, auth_method, secret_enc, description, status, created_at, updated_at, created_by,
			token_request_enabled, k8s_sa_namespace, k8s_sa_name, token_ttl_seconds, k8s_impersonate, k8s_impersonate_prefix, k8s_bind_user)
		VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		id, assetID, in.Username, in.AuthMethod, secretEnc, in.Description, now, now, actorID,
		in.TokenRequestEnabled, strings.TrimSpace(in.K8sSANamespace), strings.TrimSpace(in.K8sSAName), ttl,
		in.K8sImpersonate, canonImpersonatePrefix(in.K8sImpersonatePrefix), in.K8sBindUser)
	if err != nil {
		return Account{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "asset.account.created", "asset_account", id.String(), ip, ua, map[string]any{
		"asset_id": assetID.String(), "username": in.Username, "auth_method": in.AuthMethod,
	})
	return s.getAccount(ctx, id)
}

func (s *Service) UpdateAccount(ctx context.Context, actorID, accountID uuid.UUID, in UpdateAccountInput, ip, ua string) (Account, error) {
	acc, err := s.getAccount(ctx, accountID)
	if err != nil {
		return Account{}, err
	}
	username := acc.Username
	authMethod := acc.AuthMethod
	description := acc.Description
	status := acc.Status
	rotateAfter := acc.RotateAfterSession
	rotateOnCheckin := acc.RotateOnCheckin
	interval := acc.RotateIntervalHours
	dual := acc.DualControlCheckout
	trOn := acc.TokenRequestEnabled
	saNS := acc.K8sSANamespace
	saName := acc.K8sSAName
	ttlSec := acc.TokenTTLSeconds
	impOn := acc.K8sImpersonate
	impPrefix := acc.K8sImpersonatePrefix
	bindUser := acc.K8sBindUser
	if in.Username != nil {
		username = *in.Username
	}
	if in.AuthMethod != nil {
		authMethod = *in.AuthMethod
	}
	if in.Description != nil {
		description = *in.Description
	}
	if in.Status != nil {
		switch *in.Status {
		case "active", "disabled":
			status = *in.Status
		default:
			return Account{}, fmt.Errorf("invalid status")
		}
	}
	if in.RotateAfterSession != nil {
		rotateAfter = *in.RotateAfterSession
	}
	if in.RotateOnCheckin != nil {
		rotateOnCheckin = *in.RotateOnCheckin
	}
	if in.DualControlCheckout != nil {
		dual = *in.DualControlCheckout
	}
	if in.RotateIntervalHours != nil {
		if *in.RotateIntervalHours < 0 {
			return Account{}, fmt.Errorf("rotate_interval_hours must be >= 0")
		}
		interval = *in.RotateIntervalHours
	}
	if in.TokenRequestEnabled != nil {
		trOn = *in.TokenRequestEnabled
	}
	if in.K8sSANamespace != nil {
		saNS = strings.TrimSpace(*in.K8sSANamespace)
	}
	if in.K8sSAName != nil {
		saName = strings.TrimSpace(*in.K8sSAName)
	}
	if in.TokenTTLSeconds != nil {
		n, err := normalizeTokenTTL(*in.TokenTTLSeconds)
		if err != nil {
			return Account{}, err
		}
		ttlSec = n
	} else if n, err := normalizeTokenTTL(ttlSec); err == nil {
		ttlSec = n
	}
	if in.K8sImpersonate != nil {
		impOn = *in.K8sImpersonate
	}
	if in.K8sImpersonatePrefix != nil {
		impPrefix = canonImpersonatePrefix(*in.K8sImpersonatePrefix)
	} else {
		impPrefix = canonImpersonatePrefix(impPrefix)
	}
	if in.K8sBindUser != nil {
		bindUser = *in.K8sBindUser
	}
	if err := requireBindUserTokenRequest(bindUser, trOn); err != nil {
		return Account{}, err
	}
	var nextRotate any
	if interval > 0 {
		if acc.NextRotateAt != nil && acc.RotateIntervalHours == interval {
			nextRotate = *acc.NextRotateAt
		} else {
			nextRotate = time.Now().UTC().Add(time.Duration(interval) * time.Hour)
		}
	} else {
		nextRotate = nil
	}
	now := time.Now().UTC()
	if in.Secret != nil && *in.Secret != "" {
		enc, err := s.env.Encrypt([]byte(*in.Secret))
		if err != nil {
			return Account{}, err
		}
		_, err = s.db.Pool.Exec(ctx, `
			UPDATE asset_accounts SET username=$2, auth_method=$3, secret_enc=$4, description=$5, status=$6,
				rotate_after_session=$7, rotate_on_checkin=$8, rotate_interval_hours=$9, next_rotate_at=$10,
				dual_control_checkout=$11, token_request_enabled=$12, k8s_sa_namespace=$13, k8s_sa_name=$14,
				token_ttl_seconds=$15, k8s_impersonate=$16, k8s_impersonate_prefix=$17, k8s_bind_user=$18, updated_at=$19
			WHERE id=$1`,
			accountID, username, authMethod, enc, description, status,
			rotateAfter, rotateOnCheckin, interval, nextRotate, dual, trOn, saNS, saName, ttlSec, impOn, impPrefix, bindUser, now)
		if err != nil {
			return Account{}, err
		}
	} else {
		_, err = s.db.Pool.Exec(ctx, `
			UPDATE asset_accounts SET username=$2, auth_method=$3, description=$4, status=$5,
				rotate_after_session=$6, rotate_on_checkin=$7, rotate_interval_hours=$8, next_rotate_at=$9,
				dual_control_checkout=$10, token_request_enabled=$11, k8s_sa_namespace=$12, k8s_sa_name=$13,
				token_ttl_seconds=$14, k8s_impersonate=$15, k8s_impersonate_prefix=$16, k8s_bind_user=$17, updated_at=$18
			WHERE id=$1`,
			accountID, username, authMethod, description, status,
			rotateAfter, rotateOnCheckin, interval, nextRotate, dual, trOn, saNS, saName, ttlSec, impOn, impPrefix, bindUser, now)
		if err != nil {
			return Account{}, err
		}
	}
	_ = s.aud.Record(ctx, &actorID, "asset.account.updated", "asset_account", accountID.String(), ip, ua, map[string]any{
		"username": username, "status": status,
		"rotate_after_session": rotateAfter, "rotate_interval_hours": interval,
		"token_request_enabled": trOn, "k8s_impersonate": impOn, "k8s_bind_user": bindUser,
	})
	return s.getAccount(ctx, accountID)
}

func (s *Service) DeleteAccount(ctx context.Context, actorID, accountID uuid.UUID, ip, ua string) error {
	acc, err := s.getAccount(ctx, accountID)
	if err != nil {
		return err
	}
	_, err = s.db.Pool.Exec(ctx, `DELETE FROM asset_accounts WHERE id=$1`, accountID)
	if err != nil {
		return err
	}
	return s.aud.Record(ctx, &actorID, "asset.account.deleted", "asset_account", accountID.String(), ip, ua, map[string]any{
		"asset_id": acc.AssetID.String(), "username": acc.Username,
	})
}

func (s *Service) listAccounts(ctx context.Context, assetID uuid.UUID) ([]Account, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT a.id, a.asset_id, a.username, a.auth_method, a.secret_enc IS NOT NULL AND length(a.secret_enc)>0,
			a.description, a.status, a.last_rotated_at, a.created_at, a.updated_at, a.created_by,
			a.checkout_user_id, COALESCE(u.username,''), a.checkout_at, a.checkout_expires_at, COALESCE(a.checkout_reason,''),
			COALESCE(a.rotate_after_session,false), COALESCE(a.rotate_on_checkin,false),
			COALESCE(a.rotate_interval_hours,0), a.next_rotate_at, COALESCE(a.dual_control_checkout,false),
			COALESCE(a.token_request_enabled,false), COALESCE(a.k8s_sa_namespace,''), COALESCE(a.k8s_sa_name,''),
			COALESCE(a.token_ttl_seconds,900), COALESCE(a.k8s_impersonate,false), COALESCE(a.k8s_impersonate_prefix,'keeppam:'),
			COALESCE(a.k8s_bind_user,false)
		FROM asset_accounts a
		LEFT JOIN users u ON u.id=a.checkout_user_id
		WHERE a.asset_id=$1 ORDER BY a.username`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccountRow(rows)
		if err != nil {
			return nil, err
		}
		s.expireCheckoutIfNeeded(ctx, &a)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Service) GetAccount(ctx context.Context, id uuid.UUID) (Account, error) {
	return s.getAccount(ctx, id)
}

func (s *Service) FindAccount(ctx context.Context, assetID uuid.UUID, username string) (Account, error) {
	row := s.db.Pool.QueryRow(ctx, `
		SELECT a.id, a.asset_id, a.username, a.auth_method, a.secret_enc IS NOT NULL AND length(a.secret_enc)>0,
			a.description, a.status, a.last_rotated_at, a.created_at, a.updated_at, a.created_by,
			a.checkout_user_id, COALESCE(u.username,''), a.checkout_at, a.checkout_expires_at, COALESCE(a.checkout_reason,''),
			COALESCE(a.rotate_after_session,false), COALESCE(a.rotate_on_checkin,false),
			COALESCE(a.rotate_interval_hours,0), a.next_rotate_at, COALESCE(a.dual_control_checkout,false),
			COALESCE(a.token_request_enabled,false), COALESCE(a.k8s_sa_namespace,''), COALESCE(a.k8s_sa_name,''),
			COALESCE(a.token_ttl_seconds,900), COALESCE(a.k8s_impersonate,false), COALESCE(a.k8s_impersonate_prefix,'keeppam:'),
			COALESCE(a.k8s_bind_user,false)
		FROM asset_accounts a
		LEFT JOIN users u ON u.id=a.checkout_user_id
		WHERE a.asset_id=$1 AND a.username=$2`, assetID, username)
	a, err := scanAccountRow(row)
	if err != nil {
		return Account{}, err
	}
	s.expireCheckoutIfNeeded(ctx, &a)
	return a, nil
}

func (s *Service) getAccount(ctx context.Context, id uuid.UUID) (Account, error) {
	row := s.db.Pool.QueryRow(ctx, `
		SELECT a.id, a.asset_id, a.username, a.auth_method, a.secret_enc IS NOT NULL AND length(a.secret_enc)>0,
			a.description, a.status, a.last_rotated_at, a.created_at, a.updated_at, a.created_by,
			a.checkout_user_id, COALESCE(u.username,''), a.checkout_at, a.checkout_expires_at, COALESCE(a.checkout_reason,''),
			COALESCE(a.rotate_after_session,false), COALESCE(a.rotate_on_checkin,false),
			COALESCE(a.rotate_interval_hours,0), a.next_rotate_at, COALESCE(a.dual_control_checkout,false),
			COALESCE(a.token_request_enabled,false), COALESCE(a.k8s_sa_namespace,''), COALESCE(a.k8s_sa_name,''),
			COALESCE(a.token_ttl_seconds,900), COALESCE(a.k8s_impersonate,false), COALESCE(a.k8s_impersonate_prefix,'keeppam:'),
			COALESCE(a.k8s_bind_user,false)
		FROM asset_accounts a
		LEFT JOIN users u ON u.id=a.checkout_user_id
		WHERE a.id=$1`, id)
	a, err := scanAccountRow(row)
	if err != nil {
		return Account{}, err
	}
	s.expireCheckoutIfNeeded(ctx, &a)
	return a, nil
}

type accountScanner interface {
	Scan(dest ...any) error
}

func scanAccountRow(row accountScanner) (Account, error) {
	var a Account
	err := row.Scan(
		&a.ID, &a.AssetID, &a.Username, &a.AuthMethod, &a.HasSecret,
		&a.Description, &a.Status, &a.LastRotatedAt, &a.CreatedAt, &a.UpdatedAt, &a.CreatedBy,
		&a.CheckoutUserID, &a.CheckoutUsername, &a.CheckoutAt, &a.CheckoutExpiresAt, &a.CheckoutReason,
		&a.RotateAfterSession, &a.RotateOnCheckin, &a.RotateIntervalHours, &a.NextRotateAt, &a.DualControlCheckout,
		&a.TokenRequestEnabled, &a.K8sSANamespace, &a.K8sSAName, &a.TokenTTLSeconds,
		&a.K8sImpersonate, &a.K8sImpersonatePrefix, &a.K8sBindUser,
	)
	if err != nil {
		return a, err
	}
	a.CheckedOut = a.CheckoutUserID != nil
	return a, nil
}

func requireBindUserTokenRequest(bindUser, tokenRequest bool) error {
	if bindUser && !tokenRequest {
		return fmt.Errorf("k8s_bind_user requires token_request_enabled")
	}
	return nil
}

func normalizeTokenTTL(sec int) (int, error) {
	if sec == 0 {
		return 900, nil
	}
	if sec < 60 || sec > 86400 {
		return 0, fmt.Errorf("token_ttl_seconds must be 60..86400 (0 = 900)")
	}
	return sec, nil
}

func canonImpersonatePrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "keeppam:" {
		return "keeppam:"
	}
	if p == "-" || strings.EqualFold(p, "none") {
		return ""
	}
	return p
}

// TargetCreds returns decrypted credentials for a session proxy (never expose via HTTP).
type TargetCreds struct {
	Account    Account
	Asset      Asset
	Secret     string
	AuthMethod string
}

func (s *Service) GetTargetCreds(ctx context.Context, assetID, accountID uuid.UUID) (TargetCreds, error) {
	asset, err := s.Get(ctx, assetID)
	if err != nil {
		return TargetCreds{}, err
	}
	if asset.Status != "active" {
		return TargetCreds{}, fmt.Errorf("asset disabled")
	}
	var secretEnc []byte
	var acc Account
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id, asset_id, username, auth_method, secret_enc, description, status, created_at, updated_at, created_by,
			COALESCE(token_request_enabled,false), COALESCE(k8s_sa_namespace,''), COALESCE(k8s_sa_name,''),
			COALESCE(token_ttl_seconds,900), COALESCE(k8s_impersonate,false), COALESCE(k8s_impersonate_prefix,'keeppam:'),
			COALESCE(k8s_bind_user,false)
		FROM asset_accounts WHERE id=$1 AND asset_id=$2`, accountID, assetID).Scan(
		&acc.ID, &acc.AssetID, &acc.Username, &acc.AuthMethod, &secretEnc,
		&acc.Description, &acc.Status, &acc.CreatedAt, &acc.UpdatedAt, &acc.CreatedBy,
		&acc.TokenRequestEnabled, &acc.K8sSANamespace, &acc.K8sSAName, &acc.TokenTTLSeconds,
		&acc.K8sImpersonate, &acc.K8sImpersonatePrefix, &acc.K8sBindUser)
	if err != nil {
		return TargetCreds{}, err
	}
	if acc.Status != "active" {
		return TargetCreds{}, fmt.Errorf("account disabled")
	}
	acc.HasSecret = len(secretEnc) > 0
	certMode := asset.Protocol == "ssh" && s.sshCA != nil && s.sshCA.Mode(ctx) == "ssh_cert"
	httpsNoVault := asset.Protocol == "https"
	if len(secretEnc) == 0 {
		if !certMode && !httpsNoVault {
			return TargetCreds{}, fmt.Errorf("account has no secret")
		}
		return TargetCreds{Account: acc, Asset: asset, AuthMethod: acc.AuthMethod}, nil
	}
	plain, err := s.env.Decrypt(secretEnc)
	if err != nil {
		if httpsNoVault {
			return TargetCreds{Account: acc, Asset: asset, AuthMethod: acc.AuthMethod}, nil
		}
		return TargetCreds{}, err
	}
	secret := string(plain)
	crypto.Wipe(plain)
	return TargetCreds{Account: acc, Asset: asset, Secret: secret, AuthMethod: acc.AuthMethod}, nil
}

// WipeSecret best-effort zeroize of decrypted vault material on this value.
func (c *TargetCreds) WipeSecret() {
	if c == nil {
		return
	}
	crypto.WipeString(&c.Secret)
}

// LearnHostKey stores the first-seen SSH host key (TOFU). If a key is already stored, it must match.
func (s *Service) LearnHostKey(ctx context.Context, assetID uuid.UUID, algo string, key []byte, fp string) error {
	if len(key) == 0 {
		return fmt.Errorf("empty host key")
	}
	now := time.Now().UTC()
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE assets SET host_key_algo=$2, host_key_blob=$3, host_key_fp=$4, host_key_learned_at=$5, updated_at=$5
		WHERE id=$1 AND host_key_blob IS NULL`,
		assetID, algo, key, fp, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		_ = s.aud.Record(ctx, nil, "asset.host_key.learned", "asset", assetID.String(), "", "ssh", map[string]any{
			"algo": algo, "fingerprint": fp,
		})
		return nil
	}
	a, err := s.Get(ctx, assetID)
	if err != nil {
		return err
	}
	if len(a.HostKeyBlob) == 0 {
		return fmt.Errorf("failed to store host key")
	}
	if subtle.ConstantTimeCompare(a.HostKeyBlob, key) != 1 {
		return fmt.Errorf("host key mismatch for asset (stored %s, got %s)", a.HostKeyFingerprint, fp)
	}
	return nil
}

// ClearHostKey removes the trusted host key so the next connect re-learns (admin reset).
func (s *Service) ClearHostKey(ctx context.Context, actorID, assetID uuid.UUID, ip, ua string) (Asset, error) {
	a, err := s.Get(ctx, assetID)
	if err != nil {
		return Asset{}, err
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE assets SET host_key_algo='', host_key_blob=NULL, host_key_fp='', host_key_learned_at=NULL, updated_at=$2
		WHERE id=$1`, assetID, time.Now().UTC())
	if err != nil {
		return Asset{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "asset.host_key.cleared", "asset", assetID.String(), ip, ua, map[string]any{
		"previous_fingerprint": a.HostKeyFingerprint,
	})
	return s.Get(ctx, assetID)
}

func (s *Service) tagsFor(ctx context.Context, assetID uuid.UUID) ([]string, error) {
	rows, err := s.db.Pool.Query(ctx, `SELECT tag FROM asset_tags WHERE asset_id=$1 ORDER BY tag`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}
	return tagpath.Normalize(tags), rows.Err()
}

func setTagsTx(ctx context.Context, tx pgx.Tx, assetID uuid.UUID, tags []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM asset_tags WHERE asset_id=$1`, assetID); err != nil {
		return err
	}
	for _, tag := range tagpath.Normalize(tags) {
		if _, err := tx.Exec(ctx, `INSERT INTO asset_tags (asset_id, tag) VALUES ($1,$2) ON CONFLICT DO NOTHING`, assetID, tag); err != nil {
			return err
		}
	}
	return nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanAsset(row scannable) (Asset, error) {
	var a Asset
	err := row.Scan(&a.ID, &a.Name, &a.AssetType, &a.Hostname, &a.Address, &a.Port,
		&a.Protocol, &a.DatabaseName, &a.Description, &a.Status,
		&a.HostKeyAlgo, &a.HostKeyBlob, &a.HostKeyFingerprint, &a.HostKeyLearnedAt,
		&a.CreatedAt, &a.UpdatedAt, &a.CreatedBy, &a.ApprovalStages, &a.PamOnly, &a.FirewallAppliedAt,
		&a.ApprovalMode, &a.QuorumN, &a.QuorumM, &a.ApproverGroupID, &a.ApproverGroupName)
	if a.Tags == nil {
		a.Tags = []string{}
	}
	if len(a.ApprovalStages) == 0 {
		a.ApprovalStages = []string{"manager"}
	}
	if a.ApprovalMode == "" {
		a.ApprovalMode = "sequential"
	}
	return a, err
}

func applyAssetApproval(a *Asset, mode string, stages []string, n, m int, gid *uuid.UUID) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "sequential" {
		a.ApprovalMode = "sequential"
		a.ApprovalStages = assetApprovalStages(stages)
		a.QuorumN = 1
		a.QuorumM = 1
		a.ApproverGroupID = nil
		return nil
	}
	if mode != "quorum" {
		return fmt.Errorf("approval_mode must be sequential or quorum")
	}
	if n < 1 || n > 16 || m < 1 || m > 16 || n > m {
		return fmt.Errorf("quorum: 1 ≤ N ≤ M ≤ 16")
	}
	a.ApprovalMode = "quorum"
	a.ApprovalStages = []string{"manager"}
	a.QuorumN = n
	a.QuorumM = m
	if gid != nil && *gid == uuid.Nil {
		a.ApproverGroupID = nil
	} else {
		a.ApproverGroupID = gid
	}
	return nil
}

func assetApprovalStages(in []string) []string {
	for _, s := range in {
		if strings.EqualFold(strings.TrimSpace(s), "security") {
			return []string{"manager", "security"}
		}
	}
	return []string{"manager"}
}

func defaultPort(protocol string) int {
	switch protocol {
	case "rdp":
		return 3389
	case "vnc":
		return 5900
	case "https":
		return 443
	case "postgres":
		return 5432
	case "mysql":
		return 3306
	case "kubectl":
		return 6443
	default:
		return 22
	}
}

func IsNotFound(err error) bool {
	return err == pgx.ErrNoRows
}
