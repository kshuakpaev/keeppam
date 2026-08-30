package ai

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func (s *Service) Enqueue(ctx context.Context, kind string, ref uuid.UUID) error {
	if s == nil || s.db == nil || ref == uuid.Nil {
		return nil
	}
	cfg, err := s.Get(ctx)
	if err != nil {
		return err
	}
	if cfg.Mode == ModeOff {
		return nil
	}
	if !s.Licensed() {
		return nil
	}
	id := uuid.New()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO ai_jobs (id, kind, ref_id, status)
		SELECT $1, $2, $3, 'queued'
		WHERE NOT EXISTS (
			SELECT 1 FROM ai_jobs WHERE kind=$2 AND ref_id=$3 AND status IN ('queued','running')
		)`, id, kind, ref)
	return err
}

func (s *Service) EnqueueAfterIndex(ctx context.Context, sessionID uuid.UUID) {
	if s == nil {
		return
	}
	_ = s.Enqueue(ctx, KindSessionSummary, sessionID)
}

func (s *Service) claim(ctx context.Context) (uuid.UUID, string, uuid.UUID, error) {
	var id, ref uuid.UUID
	var kind string
	err := s.db.Pool.QueryRow(ctx, `
		UPDATE ai_jobs SET status='running', attempts=attempts+1
		WHERE id = (
			SELECT id FROM ai_jobs
			WHERE status='queued' AND attempts < 3
			ORDER BY created_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		RETURNING id, kind, ref_id`).Scan(&id, &kind, &ref)
	return id, kind, ref, err
}

func (s *Service) finish(ctx context.Context, id uuid.UUID, status, errMsg string) {
	if len(errMsg) > 500 {
		errMsg = errMsg[:500]
	}
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE ai_jobs SET status=$2, error=$3, finished_at=NOW() WHERE id=$1`, id, status, errMsg)
}

func (s *Service) requeueOrFail(ctx context.Context, id uuid.UUID, attempts int, errMsg string) {
	if attempts >= 3 {
		s.finish(ctx, id, "error", errMsg)
		if s.aud != nil {
			_ = s.aud.Record(ctx, nil, "ai.job.failed", "ai_job", id.String(), "", "ai-worker", map[string]any{"error": truncateRunes(errMsg, 120)})
		}
		return
	}
	_, _ = s.db.Pool.Exec(ctx, `UPDATE ai_jobs SET status='queued', error=$2 WHERE id=$1`, id, errMsg)
}

func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick(ctx)
		}
	}
}

func (s *Service) tick(ctx context.Context) {
	cfg, err := s.Get(ctx)
	if err != nil || cfg.Mode == ModeOff {
		return
	}
	if !s.Licensed() {
		return
	}
	for i := 0; i < 8; i++ {
		id, kind, ref, err := s.claim(ctx)
		if err != nil {
			return
		}
		jobErr := s.runJob(ctx, cfg, kind, ref)
		if jobErr != nil {
			var attempts int
			_ = s.db.Pool.QueryRow(ctx, `SELECT attempts FROM ai_jobs WHERE id=$1`, id).Scan(&attempts)
			s.requeueOrFail(ctx, id, attempts, jobErr.Error())
			s.recordRun(ctx, jobErr)
			continue
		}
		s.finish(ctx, id, "done", "")
		s.recordRun(ctx, nil)
	}
}

func (s *Service) runJob(ctx context.Context, cfg Settings, kind string, ref uuid.UUID) error {
	timeout := time.Duration(cfg.TimeoutS) * time.Second
	if timeout < 15*time.Second {
		timeout = 90 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch kind {
	case KindSessionSummary:
		return s.buildSummary(c, cfg, ref, false)
	case KindEmbedSession:
		return s.buildEmbeddings(c, cfg, ref)
	case KindRiskExplain:
		return s.buildRisk(c, cfg, ref)
	case KindApprovalBrief:
		return s.buildBrief(c, cfg, BriefJIT, ref)
	default:
		return fmt.Errorf("unknown kind %s", kind)
	}
}
