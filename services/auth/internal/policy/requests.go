package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/store"
)

type AccessRequest struct {
	ID              uuid.UUID  `json:"id"`
	AssetID         uuid.UUID  `json:"asset_id"`
	RequesterID     uuid.UUID  `json:"requester_id"`
	Reason          string     `json:"reason"`
	TicketID        string     `json:"ticket_id,omitempty"`
	DurationMinutes int        `json:"duration_minutes"`
	Status          string     `json:"status"`
	ApproverID      *uuid.UUID `json:"approver_id,omitempty"`
	DecidedAt       *time.Time `json:"decided_at,omitempty"`
	BindingID       *uuid.UUID `json:"binding_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	// Joined
	AssetName         string `json:"asset_name,omitempty"`
	AssetAddress      string `json:"asset_address,omitempty"`
	RequesterUsername string `json:"requester_username,omitempty"`
	ApproverUsername  string `json:"approver_username,omitempty"`
	RiskScore         int      `json:"risk_score"`
	RiskFactors       []string `json:"risk_factors"`
}

type CreateRequestInput struct {
	Reason          string `json:"reason"`
	TicketID        string `json:"ticket_id"`
	DurationMinutes int    `json:"duration_minutes"`
}

type ListRequestsFilter struct {
	Status       string
	RequesterID  *uuid.UUID
	Limit        int
	Offset       int
}

func (s *Service) CreateRequest(ctx context.Context, requesterID, assetID uuid.UUID, in CreateRequestInput, ip, ua string) (AccessRequest, error) {
	if in.DurationMinutes <= 0 || in.DurationMinutes > 1440 {
		return AccessRequest{}, fmt.Errorf("duration_minutes must be 1..1440")
	}
	reason := strings.TrimSpace(in.Reason)
	if len(reason) > 2000 {
		return AccessRequest{}, fmt.Errorf("reason too long")
	}
	ticket := strings.TrimSpace(in.TicketID)
	if len(ticket) > 200 {
		return AccessRequest{}, fmt.Errorf("ticket_id too long")
	}
	// Ensure asset exists
	var exists bool
	if err := s.db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM assets WHERE id=$1)`, assetID).Scan(&exists); err != nil {
		return AccessRequest{}, err
	}
	if !exists {
		return AccessRequest{}, fmt.Errorf("asset not found")
	}

	now := time.Now()
	roles, _ := s.userRoleNames(ctx, requesterID)
	ev, err := s.Evaluate(ctx, AccessCheck{
		UserID: requesterID, AssetID: assetID, RoleNames: roles, Now: now,
		TicketID: ticket, Reason: reason, ClientIP: ip,
	})
	if err != nil {
		return AccessRequest{}, err
	}
	score, factors := ev.RiskScore, ev.RiskFactors
	if !ev.OK && !ev.DeniedByRisk {
		score, factors = s.ScoreUser(ctx, requesterID, assetID, now)
	}
	if ev.DeniedByRisk && ev.RiskAction == "deny" {
		return AccessRequest{}, fmt.Errorf("%s", ev.RiskDenyMessage())
	}

	id := store.NewID()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO access_requests (id, asset_id, requester_id, reason, ticket_id, duration_minutes, status, created_at, risk_score, risk_factors)
		VALUES ($1,$2,$3,$4,$5,$6,'pending',NOW(),$7,$8)`,
		id, assetID, requesterID, reason, ticket, in.DurationMinutes, score, factors)
	if err != nil {
		if strings.Contains(err.Error(), "idx_access_requests_pending") || strings.Contains(err.Error(), "duplicate key") {
			return AccessRequest{}, fmt.Errorf("pending request already exists for this asset")
		}
		return AccessRequest{}, err
	}
	_ = s.aud.Record(ctx, &requesterID, "access.request.created", "access_request", id.String(), ip, ua, map[string]any{
		"asset_id": assetID.String(), "duration_minutes": in.DurationMinutes, "ticket_id": ticket,
		"risk_score": score, "risk_factors": factors,
	})
	return s.GetRequest(ctx, id)
}

func (s *Service) GetRequest(ctx context.Context, id uuid.UUID) (AccessRequest, error) {
	row := s.db.Pool.QueryRow(ctx, accessRequestSelect+` WHERE ar.id=$1`, id)
	return scanAccessRequest(row)
}

func (s *Service) ListRequests(ctx context.Context, f ListRequestsFilter) ([]AccessRequest, int, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	where := ` WHERE 1=1`
	args := []any{}
	i := 1
	if st := strings.TrimSpace(f.Status); st != "" {
		where += fmt.Sprintf(` AND ar.status=$%d`, i)
		args = append(args, st)
		i++
	}
	if f.RequesterID != nil {
		where += fmt.Sprintf(` AND ar.requester_id=$%d`, i)
		args = append(args, *f.RequesterID)
		i++
	}
	var total int
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM access_requests ar`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := accessRequestSelect + where + fmt.Sprintf(` ORDER BY ar.created_at DESC LIMIT $%d OFFSET $%d`, i, i+1)
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AccessRequest
	for rows.Next() {
		r, err := scanAccessRequest(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (s *Service) ApproveRequest(ctx context.Context, actorID, requestID uuid.UUID, ip, ua string) (AccessRequest, error) {
	req, err := s.GetRequest(ctx, requestID)
	if err != nil {
		return AccessRequest{}, err
	}
	if req.Status != "pending" {
		return AccessRequest{}, fmt.Errorf("request is not pending")
	}
	if req.RequesterID == actorID {
		return AccessRequest{}, fmt.Errorf("dual control: cannot approve your own access request")
	}
	uid := req.RequesterID
	b, err := s.Create(ctx, actorID, req.AssetID, CreateBindingInput{
		UserID:          &uid,
		DurationMinutes: &req.DurationMinutes,
	}, ip, ua)
	if err != nil {
		return AccessRequest{}, err
	}
	now := time.Now().UTC()
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE access_requests
		SET status='approved', approver_id=$2, decided_at=$3, binding_id=$4
		WHERE id=$1 AND status='pending'`,
		requestID, actorID, now, b.ID)
	if err != nil {
		return AccessRequest{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "access.request.approved", "access_request", requestID.String(), ip, ua, map[string]any{
		"asset_id": req.AssetID.String(), "requester_id": req.RequesterID.String(),
		"binding_id": b.ID.String(), "duration_minutes": req.DurationMinutes,
	})
	return s.GetRequest(ctx, requestID)
}

func (s *Service) DenyRequest(ctx context.Context, actorID, requestID uuid.UUID, ip, ua string) (AccessRequest, error) {
	req, err := s.GetRequest(ctx, requestID)
	if err != nil {
		return AccessRequest{}, err
	}
	if req.Status != "pending" {
		return AccessRequest{}, fmt.Errorf("request is not pending")
	}
	now := time.Now().UTC()
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE access_requests
		SET status='denied', approver_id=$2, decided_at=$3
		WHERE id=$1 AND status='pending'`, requestID, actorID, now)
	if err != nil {
		return AccessRequest{}, err
	}
	if tag.RowsAffected() == 0 {
		return AccessRequest{}, fmt.Errorf("request is not pending")
	}
	_ = s.aud.Record(ctx, &actorID, "access.request.denied", "access_request", requestID.String(), ip, ua, map[string]any{
		"asset_id": req.AssetID.String(), "requester_id": req.RequesterID.String(),
	})
	return s.GetRequest(ctx, requestID)
}

func (s *Service) CancelRequest(ctx context.Context, actorID, requestID uuid.UUID, ip, ua string) (AccessRequest, error) {
	req, err := s.GetRequest(ctx, requestID)
	if err != nil {
		return AccessRequest{}, err
	}
	if req.Status != "pending" {
		return AccessRequest{}, fmt.Errorf("request is not pending")
	}
	if req.RequesterID != actorID {
		return AccessRequest{}, fmt.Errorf("only requester can cancel")
	}
	now := time.Now().UTC()
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE access_requests SET status='cancelled', decided_at=$2
		WHERE id=$1 AND status='pending'`, requestID, now)
	if err != nil {
		return AccessRequest{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "access.request.cancelled", "access_request", requestID.String(), ip, ua, map[string]any{
		"asset_id": req.AssetID.String(),
	})
	return s.GetRequest(ctx, requestID)
}

// ExpirePending marks old pending requests as expired.
func (s *Service) ExpirePending(ctx context.Context, olderThan time.Duration) (int, error) {
	if olderThan <= 0 {
		olderThan = 24 * time.Hour
	}
	cutoff := time.Now().UTC().Add(-olderThan)
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE access_requests
		SET status='expired', decided_at=NOW()
		WHERE status='pending' AND created_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

type RequestsSummary struct {
	PendingApprove     int             `json:"pending_approve"`
	MyPending          int             `json:"my_pending"`
	MyRecentDecisions  []AccessRequest `json:"my_recent_decisions"`
}

func (s *Service) RequestsSummary(ctx context.Context, userID uuid.UUID, canApprove bool) (RequestsSummary, error) {
	var out RequestsSummary
	if canApprove {
		if err := s.db.Pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM access_requests WHERE status='pending'`).Scan(&out.PendingApprove); err != nil {
			return out, err
		}
	}
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM access_requests WHERE status='pending' AND requester_id=$1`, userID).Scan(&out.MyPending); err != nil {
		return out, err
	}
	rows, err := s.db.Pool.Query(ctx, accessRequestSelect+`
		WHERE ar.requester_id=$1
		  AND ar.status IN ('approved','denied','expired')
		  AND ar.decided_at > NOW() - INTERVAL '24 hours'
		ORDER BY ar.decided_at DESC
		LIMIT 20`, userID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanAccessRequest(rows)
		if err != nil {
			return out, err
		}
		out.MyRecentDecisions = append(out.MyRecentDecisions, r)
	}
	return out, rows.Err()
}

const accessRequestSelect = `
	SELECT ar.id, ar.asset_id, ar.requester_id, ar.reason, ar.ticket_id, ar.duration_minutes, ar.status,
		ar.approver_id, ar.decided_at, ar.binding_id, ar.created_at,
		a.name, a.address, ru.username, COALESCE(au.username,''),
		COALESCE(ar.risk_score,0), COALESCE(ar.risk_factors,'{}')
	FROM access_requests ar
	JOIN assets a ON a.id = ar.asset_id
	JOIN users ru ON ru.id = ar.requester_id
	LEFT JOIN users au ON au.id = ar.approver_id`

type requestScannable interface {
	Scan(dest ...any) error
}

func scanAccessRequest(row requestScannable) (AccessRequest, error) {
	var r AccessRequest
	err := row.Scan(
		&r.ID, &r.AssetID, &r.RequesterID, &r.Reason, &r.TicketID, &r.DurationMinutes, &r.Status,
		&r.ApproverID, &r.DecidedAt, &r.BindingID, &r.CreatedAt,
		&r.AssetName, &r.AssetAddress, &r.RequesterUsername, &r.ApproverUsername,
		&r.RiskScore, &r.RiskFactors,
	)
	if r.RiskFactors == nil {
		r.RiskFactors = []string{}
	}
	return r, err
}

func IsRequestNotFound(err error) bool { return err == pgx.ErrNoRows }
