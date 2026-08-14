package audit

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/store"
)

const (
	auditLockKey = 394817
	batchSize    = 100
	sealIdle     = time.Minute
	sealTick     = 30 * time.Second
)

type Batch struct {
	ID           uuid.UUID `json:"id"`
	Seq          int64     `json:"seq"`
	FromTS       time.Time `json:"from_ts"`
	ToTS         time.Time `json:"to_ts"`
	FirstID      uuid.UUID `json:"first_id"`
	LastID       uuid.UUID `json:"last_id"`
	EventCount   int       `json:"event_count"`
	FirstHash    string    `json:"first_hash"`
	LastHash     string    `json:"last_hash"`
	PrevBatchMAC string    `json:"prev_batch_mac"`
	MAC          string    `json:"mac"`
	CreatedAt    time.Time `json:"created_at"`
}

func BatchMAC(mac *crypto.Envelope, prevMAC, firstID, lastID string, count int, firstHash, lastHash string) string {
	if mac == nil {
		return ""
	}
	return mac.HMACHex(prevMAC, firstID, lastID, strconv.Itoa(count), firstHash, lastHash)
}

func (s *Service) RunSealer(ctx context.Context) {
	t := time.NewTicker(sealTick)
	defer t.Stop()
	for {
		if _, err := s.SealOnce(ctx, false); err != nil {
			slog.Warn("audit sealer", "err", err)
		}
		select {
		case <-ctx.Done():
			_, _ = s.SealOnce(context.Background(), true)
			return
		case <-t.C:
		}
	}
}

func (s *Service) SealOnce(ctx context.Context, flush bool) (int, error) {
	if s.mac == nil {
		return 0, nil
	}
	total := 0
	for {
		n, err := s.sealBatch(ctx, flush)
		if err != nil {
			return total, err
		}
		total += n
		if n < batchSize {
			return total, nil
		}
	}
}

func (s *Service) sealBatch(ctx context.Context, flush bool) (int, error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditLockKey); err != nil {
		return 0, err
	}

	var lastID *uuid.UUID
	var prevMAC string
	var seq int64
	err = tx.QueryRow(ctx, `
		SELECT last_id, mac, seq FROM audit_batches ORDER BY seq DESC LIMIT 1`).Scan(&lastID, &prevMAC, &seq)
	if err == pgx.ErrNoRows {
		lastID = nil
		prevMAC = ""
		seq = 0
	} else if err != nil {
		return 0, err
	}

	q := `SELECT id, ts, hash FROM audit_events`
	args := []any{}
	if lastID != nil {
		q += ` WHERE (ts, id) > (SELECT ts, id FROM audit_events WHERE id=$1)`
		args = append(args, *lastID)
	}
	q += ` ORDER BY ts ASC, id ASC LIMIT $` + itoa(len(args)+1)
	args = append(args, batchSize+1)

	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	type row struct {
		id uuid.UUID
		ts time.Time
		h  string
	}
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ts, &r.h); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(list) == 0 {
		return 0, tx.Commit(ctx)
	}
	take := len(list)
	if take > batchSize {
		take = batchSize
	}
	if take < batchSize && !flush {
		if time.Since(list[0].ts) < sealIdle {
			return 0, tx.Commit(ctx)
		}
	}
	list = list[:take]
	first, last := list[0], list[len(list)-1]
	mac := BatchMAC(s.mac, prevMAC, first.id.String(), last.id.String(), len(list), first.h, last.h)
	id := store.NewID()
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_batches
			(id, seq, from_ts, to_ts, first_id, last_id, event_count, first_hash, last_hash, prev_batch_mac, mac, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())`,
		id, seq+1, first.ts, last.ts, first.id, last.id, len(list), first.h, last.h, prevMAC, mac)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(list), nil
}

func (s *Service) ListBatches(ctx context.Context, limit int) ([]Batch, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, seq, from_ts, to_ts, first_id, last_id, event_count, first_hash, last_hash, prev_batch_mac, mac, created_at
		FROM audit_batches ORDER BY seq DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Batch
	for rows.Next() {
		var b Batch
		if err := rows.Scan(&b.ID, &b.Seq, &b.FromTS, &b.ToTS, &b.FirstID, &b.LastID, &b.EventCount,
			&b.FirstHash, &b.LastHash, &b.PrevBatchMAC, &b.MAC, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if out == nil {
		out = []Batch{}
	}
	return out, rows.Err()
}

func (s *Service) Verify(ctx context.Context) (VerifyResult, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, ts, actor_id, action, resource_type, resource_id, payload, prev_hash, hash
		FROM audit_events ORDER BY ts ASC, id ASC`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()
	var st chainState
	i := 0
	for rows.Next() {
		var e store.AuditEvent
		if err := rows.Scan(&e.ID, &e.TS, &e.ActorID, &e.Action, &e.ResourceType, &e.ResourceID,
			&e.Payload, &e.PrevHash, &e.Hash); err != nil {
			return VerifyResult{}, err
		}
		st.add(i, e)
		i++
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, err
	}
	st.finish()
	if err := s.verifyBatches(ctx, &st.res); err != nil {
		return VerifyResult{}, err
	}
	st.res.OK = len(st.res.Breaks) == 0 && st.res.BatchMACFail == 0 && st.res.BatchLinkFail == 0
	return st.res, nil
}

func (s *Service) verifyBatches(ctx context.Context, res *VerifyResult) error {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT seq, first_id, last_id, event_count, first_hash, last_hash, prev_batch_mac, mac
		FROM audit_batches ORDER BY seq ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var prevMAC string
	var lastID uuid.UUID
	haveLast := false
	for rows.Next() {
		var seq int64
		var firstID, last uuid.UUID
		var count int
		var fh, lh, pmac, mac string
		if err := rows.Scan(&seq, &firstID, &last, &count, &fh, &lh, &pmac, &mac); err != nil {
			return err
		}
		res.Batches++
		if pmac != prevMAC {
			res.BatchLinkFail++
		}
		if s.mac != nil {
			want := BatchMAC(s.mac, pmac, firstID.String(), last.String(), count, fh, lh)
			if want != mac {
				res.BatchMACFail++
			} else {
				res.BatchMACOK++
			}
		}
		prevMAC = mac
		lastID = last
		haveLast = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	unsealed := res.Events
	if haveLast {
		err := s.db.Pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM audit_events
			WHERE (ts, id) > (SELECT ts, id FROM audit_events WHERE id=$1)`, lastID).Scan(&unsealed)
		if err != nil {
			return err
		}
	}
	res.Unsealed = unsealed
	return nil
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
