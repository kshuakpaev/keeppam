package assets

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/store"
)

type CheckoutInput struct {
	Reason     string `json:"reason"`
	TTLMinutes int    `json:"ttl_minutes"`
}

type CheckinInput struct {
	// Rotate overrides account.rotate_on_checkin when set.
	Rotate *bool `json:"rotate"`
	// ApplyRemote for post-checkin rotation (default true if protocol supports).
	ApplyRemote *bool `json:"apply_remote"`
}

type CheckoutRequest struct {
	ID            uuid.UUID  `json:"id"`
	AssetID       uuid.UUID  `json:"asset_id"`
	AccountID     uuid.UUID  `json:"account_id"`
	RequesterID   uuid.UUID  `json:"requester_id"`
	Reason        string     `json:"reason"`
	TTLMinutes    int        `json:"ttl_minutes"`
	Status        string     `json:"status"`
	ApproverID    *uuid.UUID `json:"approver_id,omitempty"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	AssetName     string     `json:"asset_name,omitempty"`
	Username      string     `json:"account_username,omitempty"`
	RequesterName string     `json:"requester_username,omitempty"`
}

type CheckoutResult struct {
	Account Account          `json:"account"`
	Pending *CheckoutRequest `json:"pending_request,omitempty"`
	Status  string           `json:"status"` // checked_out | pending_approval
}

type RevealResult struct {
	Username   string `json:"username"`
	AuthMethod string `json:"auth_method"`
	Secret     string `json:"secret"`
	ExpiresAt  string `json:"checkout_expires_at,omitempty"`
}

func (s *Service) recordCheckoutEvent(ctx context.Context, assetID, accountID uuid.UUID, userID *uuid.UUID, eventType string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	b, _ := json.Marshal(detail)
	_, _ = s.db.Pool.Exec(ctx, `
		INSERT INTO secret_checkout_events (id, asset_id, account_id, user_id, event_type, detail, created_at)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,NOW())`,
		store.NewID(), assetID, accountID, userID, eventType, string(b))
}

func (s *Service) expireCheckoutIfNeeded(ctx context.Context, acc *Account) {
	if acc.CheckoutUserID == nil || acc.CheckoutExpiresAt == nil {
		return
	}
	if time.Now().UTC().Before(*acc.CheckoutExpiresAt) {
		return
	}
	uid := *acc.CheckoutUserID
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE asset_accounts
		SET checkout_user_id=NULL, checkout_at=NULL, checkout_expires_at=NULL, checkout_reason='', updated_at=NOW()
		WHERE id=$1 AND checkout_user_id IS NOT NULL`, acc.ID)
	s.recordCheckoutEvent(ctx, acc.AssetID, acc.ID, &uid, "expired", nil)
	acc.CheckoutUserID = nil
	acc.CheckoutUsername = ""
	acc.CheckoutAt = nil
	acc.CheckoutExpiresAt = nil
	acc.CheckoutReason = ""
	acc.CheckedOut = false
}

func (s *Service) Checkout(ctx context.Context, actorID, assetID, accountID uuid.UUID, in CheckoutInput, ip, ua string) (CheckoutResult, error) {
	acc, err := s.getAccount(ctx, accountID)
	if err != nil {
		return CheckoutResult{}, err
	}
	if acc.AssetID != assetID {
		return CheckoutResult{}, fmt.Errorf("account does not belong to asset")
	}
	if acc.Status != "active" {
		return CheckoutResult{}, fmt.Errorf("account disabled")
	}
	if !acc.HasSecret {
		return CheckoutResult{}, fmt.Errorf("account has no secret")
	}
	s.expireCheckoutIfNeeded(ctx, &acc)
	if acc.CheckoutUserID != nil {
		if *acc.CheckoutUserID == actorID {
			return CheckoutResult{Account: acc, Status: "checked_out"}, nil
		}
		return CheckoutResult{}, fmt.Errorf("already checked out by another user until %s", acc.CheckoutExpiresAt.Format(time.RFC3339))
	}

	ttl := in.TTLMinutes
	if ttl <= 0 {
		ttl = 60
	}
	if ttl > 24*60 {
		ttl = 24 * 60
	}
	reason := strings.TrimSpace(in.Reason)

	if acc.DualControlCheckout {
		reqID := store.NewID()
		now := time.Now().UTC()
		exp := now.Add(24 * time.Hour)
		_, err := s.db.Pool.Exec(ctx, `
			INSERT INTO secret_checkout_requests
				(id, asset_id, account_id, requester_id, reason, ttl_minutes, status, created_at, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8)`,
			reqID, assetID, accountID, actorID, reason, ttl, now, exp)
		if err != nil {
			return CheckoutResult{}, err
		}
		_ = s.aud.Record(ctx, &actorID, "asset.account.checkout.requested", "asset_account", accountID.String(), ip, ua, map[string]any{
			"asset_id": assetID.String(), "ttl_minutes": ttl, "dual_control": true,
		})
		s.recordCheckoutEvent(ctx, assetID, accountID, &actorID, "checkout_requested", map[string]any{"request_id": reqID.String()})
		req, _ := s.getCheckoutRequest(ctx, reqID)
		return CheckoutResult{Account: acc, Pending: &req, Status: "pending_approval"}, nil
	}

	now := time.Now().UTC()
	exp := now.Add(time.Duration(ttl) * time.Minute)
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE asset_accounts
		SET checkout_user_id=$2, checkout_at=$3, checkout_expires_at=$4, checkout_reason=$5, updated_at=$3
		WHERE id=$1 AND checkout_user_id IS NULL`,
		accountID, actorID, now, exp, reason)
	if err != nil {
		return CheckoutResult{}, err
	}
	if tag.RowsAffected() == 0 {
		return CheckoutResult{}, fmt.Errorf("checkout race: already held")
	}
	_ = s.aud.Record(ctx, &actorID, "asset.account.checkout", "asset_account", accountID.String(), ip, ua, map[string]any{
		"asset_id": assetID.String(), "ttl_minutes": ttl,
	})
	s.recordCheckoutEvent(ctx, assetID, accountID, &actorID, "checkout", map[string]any{"ttl_minutes": ttl})
	out, err := s.getAccount(ctx, accountID)
	if err != nil {
		return CheckoutResult{}, err
	}
	return CheckoutResult{Account: out, Status: "checked_out"}, nil
}

func (s *Service) activateCheckout(ctx context.Context, accountID, userID uuid.UUID, reason string, ttlMinutes int) (Account, error) {
	now := time.Now().UTC()
	exp := now.Add(time.Duration(ttlMinutes) * time.Minute)
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE asset_accounts
		SET checkout_user_id=$2, checkout_at=$3, checkout_expires_at=$4, checkout_reason=$5, updated_at=$3
		WHERE id=$1`, accountID, userID, now, exp, reason)
	if err != nil {
		return Account{}, err
	}
	return s.getAccount(ctx, accountID)
}

func (s *Service) Checkin(ctx context.Context, actorID, assetID, accountID uuid.UUID, in CheckinInput, ip, ua string) (CheckoutResult, error) {
	acc, err := s.getAccount(ctx, accountID)
	if err != nil {
		return CheckoutResult{}, err
	}
	if acc.AssetID != assetID {
		return CheckoutResult{}, fmt.Errorf("account does not belong to asset")
	}
	s.expireCheckoutIfNeeded(ctx, &acc)
	if acc.CheckoutUserID == nil {
		return CheckoutResult{Account: acc, Status: "idle"}, nil
	}
	if *acc.CheckoutUserID != actorID {
		return CheckoutResult{}, fmt.Errorf("checked out by another user; use force-checkin")
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE asset_accounts
		SET checkout_user_id=NULL, checkout_at=NULL, checkout_expires_at=NULL, checkout_reason='', updated_at=NOW()
		WHERE id=$1 AND checkout_user_id=$2`, accountID, actorID)
	if err != nil {
		return CheckoutResult{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "asset.account.checkin", "asset_account", accountID.String(), ip, ua, map[string]any{
		"asset_id": assetID.String(),
	})
	s.recordCheckoutEvent(ctx, assetID, accountID, &actorID, "checkin", nil)

	doRotate := acc.RotateOnCheckin
	if in.Rotate != nil {
		doRotate = *in.Rotate
	}
	out, err := s.getAccount(ctx, accountID)
	if err != nil {
		return CheckoutResult{}, err
	}
	if doRotate {
		apply := true
		if in.ApplyRemote != nil {
			apply = *in.ApplyRemote
		}
		_, rerr := s.RotateSecret(ctx, actorID, assetID, accountID, RotateInput{ApplyRemote: &apply}, ip, ua)
		if rerr != nil {
			return CheckoutResult{Account: out, Status: "checked_in"}, fmt.Errorf("checked in, but rotate failed: %w", rerr)
		}
		out, _ = s.getAccount(ctx, accountID)
		s.recordCheckoutEvent(ctx, assetID, accountID, &actorID, "rotate_on_checkin", nil)
	}
	return CheckoutResult{Account: out, Status: "checked_in"}, nil
}

func (s *Service) ForceCheckin(ctx context.Context, actorID, assetID, accountID uuid.UUID, ip, ua string) (Account, error) {
	acc, err := s.getAccount(ctx, accountID)
	if err != nil {
		return Account{}, err
	}
	if acc.AssetID != assetID {
		return Account{}, fmt.Errorf("account does not belong to asset")
	}
	var prev *uuid.UUID
	if acc.CheckoutUserID != nil {
		u := *acc.CheckoutUserID
		prev = &u
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE asset_accounts
		SET checkout_user_id=NULL, checkout_at=NULL, checkout_expires_at=NULL, checkout_reason='', updated_at=NOW()
		WHERE id=$1`, accountID)
	if err != nil {
		return Account{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "asset.account.force_checkin", "asset_account", accountID.String(), ip, ua, map[string]any{
		"asset_id": assetID.String(), "previous_holder": uuidPtrStr(prev),
	})
	s.recordCheckoutEvent(ctx, assetID, accountID, &actorID, "force_checkin", map[string]any{"previous_holder": uuidPtrStr(prev)})
	return s.getAccount(ctx, accountID)
}

func (s *Service) RevealSecret(ctx context.Context, actorID, assetID, accountID uuid.UUID, ip, ua string) (RevealResult, error) {
	acc, err := s.getAccount(ctx, accountID)
	if err != nil {
		return RevealResult{}, err
	}
	if acc.AssetID != assetID {
		return RevealResult{}, fmt.Errorf("account does not belong to asset")
	}
	s.expireCheckoutIfNeeded(ctx, &acc)
	if acc.CheckoutUserID == nil || *acc.CheckoutUserID != actorID {
		return RevealResult{}, fmt.Errorf("secret reveal requires active checkout by you")
	}
	creds, err := s.GetTargetCreds(ctx, assetID, accountID)
	if err != nil {
		return RevealResult{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "asset.account.secret_revealed", "asset_account", accountID.String(), ip, ua, map[string]any{
		"asset_id": assetID.String(),
	})
	s.recordCheckoutEvent(ctx, assetID, accountID, &actorID, "reveal", nil)
	exp := ""
	if acc.CheckoutExpiresAt != nil {
		exp = acc.CheckoutExpiresAt.UTC().Format(time.RFC3339)
	}
	return RevealResult{
		Username:   creds.Account.Username,
		AuthMethod: creds.AuthMethod,
		Secret:     creds.Secret,
		ExpiresAt:  exp,
	}, nil
}

func (s *Service) ListCheckoutRequests(ctx context.Context, onlyPending bool) ([]CheckoutRequest, error) {
	q := `
		SELECT r.id, r.asset_id, r.account_id, r.requester_id, r.reason, r.ttl_minutes, r.status,
			r.approver_id, r.decided_at, r.created_at, r.expires_at,
			a.name, acc.username, u.username
		FROM secret_checkout_requests r
		JOIN assets a ON a.id=r.asset_id
		JOIN asset_accounts acc ON acc.id=r.account_id
		JOIN users u ON u.id=r.requester_id`
	if onlyPending {
		q += ` WHERE r.status='pending' AND r.expires_at > NOW()`
	}
	q += ` ORDER BY r.created_at DESC LIMIT 200`
	rows, err := s.db.Pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckoutRequest
	for rows.Next() {
		var r CheckoutRequest
		if err := rows.Scan(&r.ID, &r.AssetID, &r.AccountID, &r.RequesterID, &r.Reason, &r.TTLMinutes, &r.Status,
			&r.ApproverID, &r.DecidedAt, &r.CreatedAt, &r.ExpiresAt,
			&r.AssetName, &r.Username, &r.RequesterName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Service) getCheckoutRequest(ctx context.Context, id uuid.UUID) (CheckoutRequest, error) {
	var r CheckoutRequest
	err := s.db.Pool.QueryRow(ctx, `
		SELECT r.id, r.asset_id, r.account_id, r.requester_id, r.reason, r.ttl_minutes, r.status,
			r.approver_id, r.decided_at, r.created_at, r.expires_at,
			a.name, acc.username, u.username
		FROM secret_checkout_requests r
		JOIN assets a ON a.id=r.asset_id
		JOIN asset_accounts acc ON acc.id=r.account_id
		JOIN users u ON u.id=r.requester_id
		WHERE r.id=$1`, id).Scan(
		&r.ID, &r.AssetID, &r.AccountID, &r.RequesterID, &r.Reason, &r.TTLMinutes, &r.Status,
		&r.ApproverID, &r.DecidedAt, &r.CreatedAt, &r.ExpiresAt,
		&r.AssetName, &r.Username, &r.RequesterName)
	return r, err
}

func (s *Service) ApproveCheckoutRequest(ctx context.Context, actorID, requestID uuid.UUID, ip, ua string) (CheckoutResult, error) {
	req, err := s.getCheckoutRequest(ctx, requestID)
	if err != nil {
		return CheckoutResult{}, err
	}
	if req.Status != "pending" {
		return CheckoutResult{}, fmt.Errorf("request is %s", req.Status)
	}
	if time.Now().UTC().After(req.ExpiresAt) {
		_, _ = s.db.Pool.Exec(ctx, `UPDATE secret_checkout_requests SET status='expired', decided_at=NOW() WHERE id=$1`, requestID)
		return CheckoutResult{}, fmt.Errorf("request expired")
	}
	if req.RequesterID == actorID {
		return CheckoutResult{}, fmt.Errorf("dual control: cannot approve your own checkout request")
	}
	acc, err := s.getAccount(ctx, req.AccountID)
	if err != nil {
		return CheckoutResult{}, err
	}
	s.expireCheckoutIfNeeded(ctx, &acc)
	if acc.CheckoutUserID != nil {
		_, _ = s.db.Pool.Exec(ctx, `
			UPDATE secret_checkout_requests SET status='denied', approver_id=$2, decided_at=NOW() WHERE id=$1`, requestID, actorID)
		return CheckoutResult{}, fmt.Errorf("account already checked out")
	}
	now := time.Now().UTC()
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE secret_checkout_requests SET status='approved', approver_id=$2, decided_at=$3 WHERE id=$1 AND status='pending'`,
		requestID, actorID, now)
	if err != nil {
		return CheckoutResult{}, err
	}
	out, err := s.activateCheckout(ctx, req.AccountID, req.RequesterID, req.Reason, req.TTLMinutes)
	if err != nil {
		return CheckoutResult{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "asset.account.checkout.approved", "asset_account", req.AccountID.String(), ip, ua, map[string]any{
		"request_id": requestID.String(), "requester_id": req.RequesterID.String(),
	})
	s.recordCheckoutEvent(ctx, req.AssetID, req.AccountID, &actorID, "checkout_approved", map[string]any{
		"request_id": requestID.String(), "requester_id": req.RequesterID.String(),
	})
	s.recordCheckoutEvent(ctx, req.AssetID, req.AccountID, &req.RequesterID, "checkout", map[string]any{"via": "dual_control"})
	req.Status = "approved"
	req.ApproverID = &actorID
	req.DecidedAt = &now
	return CheckoutResult{Account: out, Status: "checked_out", Pending: &req}, nil
}

func (s *Service) DenyCheckoutRequest(ctx context.Context, actorID, requestID uuid.UUID, ip, ua string) (CheckoutRequest, error) {
	req, err := s.getCheckoutRequest(ctx, requestID)
	if err != nil {
		return CheckoutRequest{}, err
	}
	if req.Status != "pending" {
		return CheckoutRequest{}, fmt.Errorf("request is %s", req.Status)
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE secret_checkout_requests SET status='denied', approver_id=$2, decided_at=NOW() WHERE id=$1`, requestID, actorID)
	if err != nil {
		return CheckoutRequest{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "asset.account.checkout.denied", "asset_account", req.AccountID.String(), ip, ua, map[string]any{
		"request_id": requestID.String(),
	})
	s.recordCheckoutEvent(ctx, req.AssetID, req.AccountID, &actorID, "checkout_denied", map[string]any{"request_id": requestID.String()})
	now := time.Now().UTC()
	req.Status = "denied"
	req.ApproverID = &actorID
	req.DecidedAt = &now
	return req, nil
}

// ExpireCheckouts clears overdue holds and pending dual-control requests.
func (s *Service) ExpireCheckouts(ctx context.Context) (int, error) {
	rows, err := s.db.Pool.Query(ctx, `
		UPDATE asset_accounts
		SET checkout_user_id=NULL, checkout_at=NULL, checkout_expires_at=NULL, checkout_reason='', updated_at=NOW()
		WHERE checkout_user_id IS NOT NULL AND checkout_expires_at IS NOT NULL AND checkout_expires_at < NOW()
		RETURNING id, asset_id, checkout_user_id`)
	if err != nil {
		return 0, err
	}
	n := 0
	for rows.Next() {
		var id, assetID, uid uuid.UUID
		if err := rows.Scan(&id, &assetID, &uid); err != nil {
			rows.Close()
			return n, err
		}
		s.recordCheckoutEvent(ctx, assetID, id, &uid, "expired", nil)
		n++
	}
	rows.Close()
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE secret_checkout_requests SET status='expired', decided_at=NOW()
		WHERE status='pending' AND expires_at < NOW()`)
	return n, nil
}

// rotateLock is held on one PG session while scheduled rotation runs (HA: only one API replica rotates).
const rotateLock int64 = 87201606

// RunDueRotations rotates accounts whose next_rotate_at is due.
func (s *Service) RunDueRotations(ctx context.Context) (int, error) {
	conn, err := s.db.Pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, rotateLock).Scan(&got); err != nil {
		return 0, err
	}
	if !got {
		return 0, nil
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, rotateLock)
	}()

	rows, err := conn.Query(ctx, `
		SELECT id, asset_id FROM asset_accounts
		WHERE status='active' AND rotate_interval_hours > 0
		  AND next_rotate_at IS NOT NULL AND next_rotate_at <= NOW()
		  AND checkout_user_id IS NULL
		ORDER BY next_rotate_at ASC
		LIMIT 20`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type pair struct{ acc, asset uuid.UUID }
	var due []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.acc, &p.asset); err != nil {
			return 0, err
		}
		due = append(due, p)
	}
	n := 0
	system := uuid.Nil
	for _, p := range due {
		apply := true
		_, err := s.RotateSecret(ctx, system, p.asset, p.acc, RotateInput{ApplyRemote: &apply}, "", "scheduler")
		if err != nil {
			// still bump next_rotate_at to avoid tight failure loop
			_, _ = s.db.Pool.Exec(ctx, `
				UPDATE asset_accounts SET next_rotate_at = NOW() + (rotate_interval_hours || ' hours')::interval
				WHERE id=$1 AND rotate_interval_hours > 0`, p.acc)
			s.recordCheckoutEvent(ctx, p.asset, p.acc, nil, "schedule_rotate_failed", map[string]any{"error": truncate(err.Error(), 200)})
			continue
		}
		s.recordCheckoutEvent(ctx, p.asset, p.acc, nil, "schedule_rotate", nil)
		n++
	}
	return n, nil
}

// MaybeRotateAfterSession rotates vault secret when policy says so and no other active sessions use the account.
func (s *Service) MaybeRotateAfterSession(ctx context.Context, accountID uuid.UUID) error {
	acc, err := s.getAccount(ctx, accountID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}
	if !acc.RotateAfterSession || !acc.HasSecret {
		return nil
	}
	if acc.CheckoutUserID != nil {
		return nil
	}
	var active int
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions
		WHERE account_id=$1 AND status='active'`, accountID).Scan(&active)
	if err != nil {
		return err
	}
	if active > 0 {
		return nil
	}
	apply := true
	_, err = s.RotateSecret(ctx, uuid.Nil, acc.AssetID, accountID, RotateInput{ApplyRemote: &apply}, "", "session-end")
	if err != nil {
		s.recordCheckoutEvent(ctx, acc.AssetID, accountID, nil, "rotate_after_session_failed", map[string]any{"error": truncate(err.Error(), 200)})
		return err
	}
	s.recordCheckoutEvent(ctx, acc.AssetID, accountID, nil, "rotate_after_session", nil)
	return nil
}

func uuidPtrStr(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
