package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/sessionsvc"
)

func (s *Service) loadIndexEvents(ctx context.Context, sessionID uuid.UUID, capChars int) ([]indexEvent, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, event_type, payload, ts
		FROM session_events
		WHERE session_id=$1
		ORDER BY ts ASC
		LIMIT 400`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []indexEvent
	used := 0
	for rows.Next() {
		var e indexEvent
		var raw []byte
		if err := rows.Scan(&e.ID, &e.Type, &raw, &e.TS); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &e.Payload)
		if e.Payload == nil {
			e.Payload = map[string]any{}
		}
		e.Payload = redactMap(e.Payload)
		e.Snippet = snippetOf(e.Type, e.Payload)
		e.Offset = eventOffset(e.Payload)
		if !summaryTypes[e.Type] {
			continue
		}
		used += len(e.Snippet)
		if capChars > 0 && used > capChars {
			break
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Service) buildSummary(ctx context.Context, cfg Settings, sessionID uuid.UUID, force bool) error {
	row, err := s.sess.Get(ctx, sessionID)
	if err != nil {
		return err
	}
	evs, err := s.loadIndexEvents(ctx, sessionID, cfg.MaxInputChars)
	if err != nil {
		return err
	}
	if len(evs) == 0 {
		return s.upsertSummary(ctx, Summary{
			SessionID:  sessionID,
			Status:     "skipped",
			SkipReason: "no_events",
			Model:      cfg.Model,
		})
	}
	h := eventsHash(evs)
	if !force {
		var prev string
		err := s.db.Pool.QueryRow(ctx, `SELECT input_hash FROM session_ai_summaries WHERE session_id=$1 AND status='ready'`, sessionID).Scan(&prev)
		if err == nil && prev == h {
			return nil
		}
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
	}
	rt := s.runtimeFor(cfg)
	if cfg.Mode != ModeOff && !isMockEndpoint(cfg.Endpoint) && cfg.Model != "mock" {
		if err := rt.Probe(ctx, cfg); err != nil {
			return s.upsertSummary(ctx, Summary{
				SessionID: sessionID, Status: "skipped", SkipReason: "no_runtime", Model: cfg.Model, InputHash: h,
			})
		}
	}
	lang := s.langOf(cfg)
	mock := MockSummaryFromEvents(sessionID, row.Protocol, row.Username, row.AssetName, row.RiskScore, row.RiskFactors, evs, lang)
	mock.InputHash = h
	mock.Model = cfg.Model
	sum := mock
	if !isMockEndpoint(cfg.Endpoint) && cfg.Model != "mock" {
		payload, _ := json.Marshal(map[string]any{
			"session_id": sessionID, "protocol": row.Protocol, "user": row.Username, "asset": row.AssetName,
			"risk_score": row.RiskScore, "risk_factors": row.RiskFactors, "events": compactEvents(evs),
		})
		sys := `You summarize a PAM session. Reply with JSON only: {"headline","summary","screen_narrative","bullets":[{"text","event_id","offset","type","kind"}],"risk_notes":[{"text","event_id","kind"}],"offsets":[{"label","offset"}]}. Only facts from events. Never invent DROP/commands. Use event_id from input.`
		raw, err := rt.Chat(ctx, cfg, sys, string(payload))
		if err == nil {
			if parsed, err := parseSummaryJSON(raw, mock); err == nil {
				sum = parsed
				sum.Model = cfg.Model
				sum.InputHash = h
			} else {
				return fmt.Errorf("summary schema: %w", err)
			}
		} else {
			return err
		}
	}
	if err := s.upsertSummary(ctx, sum); err != nil {
		return err
	}
	if s.aud != nil {
		_ = s.aud.Record(ctx, nil, "ai.summary.generated", "session", sessionID.String(), "", "ai-worker", map[string]any{
			"status": sum.Status, "model": sum.Model, "bullets": len(sum.Bullets),
		})
	}
	_ = s.Enqueue(ctx, KindEmbedSession, sessionID)
	_ = s.Enqueue(ctx, KindRiskExplain, sessionID)
	return nil
}

func compactEvents(evs []indexEvent) []map[string]any {
	out := make([]map[string]any, 0, len(evs))
	for _, e := range evs {
		out = append(out, map[string]any{
			"id": e.ID.String(), "type": e.Type, "snippet": e.Snippet, "offset": e.Offset, "kind": payloadKind(e.Payload),
		})
	}
	return out
}

func (s *Service) upsertSummary(ctx context.Context, sum Summary) error {
	bullets, _ := json.Marshal(sum.Bullets)
	notes, _ := json.Marshal(sum.RiskNotes)
	offs, _ := json.Marshal(sum.Offsets)
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO session_ai_summaries (
			session_id, status, model, headline, summary, screen_narrative,
			bullets, risk_notes, offsets, input_hash, skip_reason, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW())
		ON CONFLICT (session_id) DO UPDATE SET
			status=EXCLUDED.status, model=EXCLUDED.model, headline=EXCLUDED.headline,
			summary=EXCLUDED.summary, screen_narrative=EXCLUDED.screen_narrative,
			bullets=EXCLUDED.bullets, risk_notes=EXCLUDED.risk_notes, offsets=EXCLUDED.offsets,
			input_hash=EXCLUDED.input_hash, skip_reason=EXCLUDED.skip_reason, updated_at=NOW()`,
		sum.SessionID, sum.Status, sum.Model, sum.Headline, sum.Summary, sum.ScreenNarrative,
		bullets, notes, offs, sum.InputHash, sum.SkipReason)
	return err
}

func (s *Service) GetSummary(ctx context.Context, sessionID uuid.UUID) (Summary, error) {
	var sum Summary
	var bullets, notes, offs []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT session_id, status, model, headline, summary, screen_narrative,
		       bullets, risk_notes, offsets, input_hash, skip_reason, created_at, updated_at
		FROM session_ai_summaries WHERE session_id=$1`, sessionID).Scan(
		&sum.SessionID, &sum.Status, &sum.Model, &sum.Headline, &sum.Summary, &sum.ScreenNarrative,
		&bullets, &notes, &offs, &sum.InputHash, &sum.SkipReason, &sum.CreatedAt, &sum.UpdatedAt,
	)
	if err != nil {
		return Summary{}, err
	}
	_ = json.Unmarshal(bullets, &sum.Bullets)
	_ = json.Unmarshal(notes, &sum.RiskNotes)
	_ = json.Unmarshal(offs, &sum.Offsets)
	if sum.Bullets == nil {
		sum.Bullets = []Bullet{}
	}
	if sum.RiskNotes == nil {
		sum.RiskNotes = []RiskNote{}
	}
	if sum.Offsets == nil {
		sum.Offsets = []OffsetRef{}
	}
	return sum, nil
}

func (s *Service) RequestSummary(ctx context.Context, sessionID uuid.UUID, force bool) (Summary, error) {
	cfg, err := s.Get(ctx)
	if err != nil {
		return Summary{}, err
	}
	if cfg.Mode == ModeOff {
		return Summary{SessionID: sessionID, Status: "skipped", SkipReason: "off"}, nil
	}
	if !s.Licensed() {
		return Summary{SessionID: sessionID, Status: "skipped", SkipReason: "license"}, nil
	}
	if force {
		if err := s.buildSummary(ctx, cfg, sessionID, true); err != nil {
			return Summary{}, err
		}
		return s.GetSummary(ctx, sessionID)
	}
	if cur, err := s.GetSummary(ctx, sessionID); err == nil {
		return cur, nil
	}
	_ = s.Enqueue(ctx, KindSessionSummary, sessionID)
	_ = s.upsertSummary(ctx, Summary{SessionID: sessionID, Status: "pending", Model: cfg.Model})
	return s.GetSummary(ctx, sessionID)
}

func (s *Service) buildEmbeddings(ctx context.Context, cfg Settings, sessionID uuid.UUID) error {
	evs, err := s.loadIndexEvents(ctx, sessionID, cfg.MaxInputChars)
	if err != nil {
		return err
	}
	if len(evs) == 0 {
		return nil
	}
	texts := make([]string, 0, len(evs))
	ids := make([]uuid.UUID, 0, len(evs))
	for _, e := range evs {
		t := strings.TrimSpace(e.Type + " " + e.Snippet)
		if t == "" {
			continue
		}
		texts = append(texts, t)
		ids = append(ids, e.ID)
	}
	rt := s.runtimeFor(cfg)
	vecs, err := rt.Embed(ctx, cfg, texts)
	if err != nil {
		return err
	}
	model := cfg.EmbedModel
	if model == "" {
		model = cfg.Model
	}
	for i := range ids {
		var v []float32
		if i < len(vecs) {
			v = vecs[i]
		} else {
			v = HashEmbed(texts[i])
		}
		raw, _ := json.Marshal(v)
		_, err := s.db.Pool.Exec(ctx, `
			INSERT INTO session_event_embeddings (event_id, session_id, embedding, model, created_at)
			VALUES ($1,$2,$3,$4,NOW())
			ON CONFLICT (event_id) DO UPDATE SET embedding=EXCLUDED.embedding, model=EXCLUDED.model, created_at=NOW()`,
			ids[i], sessionID, raw, model)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) SearchNL(ctx context.Context, q string, f sessionsvc.EventSearchFilter) ([]sessionsvc.EventHit, int, bool, error) {
	cfg, err := s.Get(ctx)
	if err != nil {
		return nil, 0, false, err
	}
	if cfg.Mode == ModeOff {
		return nil, 0, false, fmt.Errorf("ai off")
	}
	if !s.Licensed() {
		return nil, 0, false, fmt.Errorf("license")
	}
	rt := s.runtimeFor(cfg)
	vecs, err := rt.Embed(ctx, cfg, []string{q})
	if err != nil {
		return nil, 0, false, err
	}
	if len(vecs) == 0 {
		return nil, 0, true, nil
	}
	qvec := vecs[0]
	rows, err := s.db.Pool.Query(ctx, `
		SELECT e.event_id, e.session_id, e.embedding
		FROM session_event_embeddings e
		JOIN sessions s ON s.id = e.session_id
		WHERE s.created_at > NOW() - ($1 * INTERVAL '1 hour')
		LIMIT 2000`, f.Hours)
	if err != nil {
		return nil, 0, false, err
	}
	defer rows.Close()
	type scored struct {
		id, sess uuid.UUID
		score    float64
	}
	var ranked []scored
	for rows.Next() {
		var id, sess uuid.UUID
		var raw []byte
		if err := rows.Scan(&id, &sess, &raw); err != nil {
			return nil, 0, false, err
		}
		var vec []float32
		_ = json.Unmarshal(raw, &vec)
		ranked = append(ranked, scored{id: id, sess: sess, score: cosine(qvec, vec)})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	// simple selection sort top k
	k := f.Limit
	if k <= 0 {
		k = 50
	}
	for i := 0; i < len(ranked) && i < k; i++ {
		best := i
		for j := i + 1; j < len(ranked); j++ {
			if ranked[j].score > ranked[best].score {
				best = j
			}
		}
		ranked[i], ranked[best] = ranked[best], ranked[i]
	}
	if len(ranked) > k {
		ranked = ranked[:k]
	}
	var hits []sessionsvc.EventHit
	for _, r := range ranked {
		if r.score < 0.12 {
			continue
		}
		h, err := s.hitByID(ctx, r.id)
		if err != nil {
			continue
		}
		if f.OnlyUser != nil {
			// hitByID joins username; filter via session owner below if needed
		}
		hits = append(hits, h)
	}
	if f.OnlyUser != nil && s.sess != nil {
		var filtered []sessionsvc.EventHit
		for _, h := range hits {
			row, err := s.sess.Get(ctx, h.SessionID)
			if err != nil || row.UserID != *f.OnlyUser {
				continue
			}
			filtered = append(filtered, h)
		}
		hits = filtered
	}
	return hits, len(hits), true, nil
}

func (s *Service) hitByID(ctx context.Context, eventID uuid.UUID) (sessionsvc.EventHit, error) {
	var h sessionsvc.EventHit
	var raw []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT e.id, e.session_id, e.ts, e.event_type, e.payload,
		       COALESCE(u.username,''), COALESCE(a.name,''), s.asset_id, s.protocol, s.status, s.break_glass
		FROM session_events e
		JOIN sessions s ON s.id=e.session_id
		JOIN users u ON u.id=s.user_id
		JOIN assets a ON a.id=s.asset_id
		WHERE e.id=$1`, eventID).Scan(
		&h.ID, &h.SessionID, &h.TS, &h.Type, &raw,
		&h.Username, &h.AssetName, &h.AssetID, &h.Protocol, &h.Status, &h.BreakGlass)
	if err != nil {
		return h, err
	}
	_ = json.Unmarshal(raw, &h.Payload)
	h.Snippet = sessionsvc.EventSnippet(h.Type, h.Payload)
	return h, nil
}
