package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Service) buildRisk(ctx context.Context, cfg Settings, sessionID uuid.UUID) error {
	row, err := s.sess.Get(ctx, sessionID)
	if err != nil {
		return err
	}
	factors := knownFactors(row.RiskFactors)
	lang := s.langOf(cfg)
	text := explainFactors(factors, row.RiskScore, lang)
	rt := s.runtimeFor(cfg)
	if !isMockEndpoint(cfg.Endpoint) && cfg.Model != "mock" {
		payload, _ := json.Marshal(map[string]any{"risk_score": row.RiskScore, "factors": factors})
		sys := `Explain these PAM risk factors in 3-6 sentences. Only mention codes from the JSON. JSON only: {"text":"..."}`
		raw, err := rt.Chat(ctx, cfg, sys, string(payload))
		if err == nil {
			var parsed struct {
				Text string `json:"text"`
			}
			if json.Unmarshal([]byte(extractJSON(raw)), &parsed) == nil && parsed.Text != "" {
				text = filterExplainText(parsed.Text, factors)
			}
		}
	}
	rawF, _ := json.Marshal(factors)
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO session_ai_risk (session_id, status, model, text, factors, created_at, updated_at)
		VALUES ($1,'ready',$2,$3,$4,NOW(),NOW())
		ON CONFLICT (session_id) DO UPDATE SET
			status='ready', model=EXCLUDED.model, text=EXCLUDED.text, factors=EXCLUDED.factors, updated_at=NOW()`,
		sessionID, cfg.Model, text, rawF)
	return err
}

func (s *Service) GetRisk(ctx context.Context, sessionID uuid.UUID) (RiskExplain, error) {
	var out RiskExplain
	var raw []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT session_id, status, model, text, factors, updated_at FROM session_ai_risk WHERE session_id=$1`,
		sessionID).Scan(&out.SessionID, &out.Status, &out.Model, &out.Text, &raw, &out.UpdatedAt)
	if err == pgx.ErrNoRows {
		row, err2 := s.sess.Get(ctx, sessionID)
		if err2 != nil {
			return RiskExplain{}, err2
		}
		cfg, _ := s.Get(ctx)
		factors := knownFactors(row.RiskFactors)
		return RiskExplain{
			SessionID: sessionID,
			Status:    "ready",
			Model:     "dict",
			Text:      explainFactors(factors, row.RiskScore, s.langOf(cfg)),
			Factors:   factors,
			UpdatedAt: time.Now().UTC(),
		}, nil
	}
	if err != nil {
		return RiskExplain{}, err
	}
	_ = json.Unmarshal(raw, &out.Factors)
	out.Factors = knownFactors(out.Factors)
	out.Text = filterExplainText(out.Text, out.Factors)
	return out, nil
}

func (s *Service) collectJITFacts(ctx context.Context, requestID uuid.UUID) (map[string]any, error) {
	req, err := s.policy.GetRequest(ctx, requestID)
	if err != nil {
		return nil, err
	}
	facts := map[string]any{
		"request_id": requestID.String(),
		"requester":  req.RequesterUsername,
		"asset":      req.AssetName,
		"asset_id":   req.AssetID.String(),
		"reason":     req.Reason,
		"ticket":     req.TicketID,
		"risk_score": req.RiskScore,
		"risk_factors": knownFactors(req.RiskFactors),
		"status":     req.Status,
	}
	var sessN, distinct int
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(DISTINCT asset_id)
		FROM sessions WHERE user_id=$1 AND created_at > NOW() - INTERVAL '30 days'
		AND status IN ('pending','active','ended')`, req.RequesterID).Scan(&sessN, &distinct)
	facts["sessions_30d"] = sessN
	facts["assets_30d"] = distinct
	var seen bool
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM sessions WHERE user_id=$1 AND asset_id=$2
			AND created_at > NOW() - INTERVAL '30 days' AND status IN ('pending','active','ended')
		)`, req.RequesterID, req.AssetID).Scan(&seen)
	facts["asset_in_baseline"] = seen
	if !seen {
		facts["new_asset"] = true
	}
	var prevOK, prevDeny int
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE status='approved'), COUNT(*) FILTER (WHERE status='denied')
		FROM access_requests WHERE requester_id=$1 AND asset_id=$2 AND id<>$3`,
		req.RequesterID, req.AssetID, requestID).Scan(&prevOK, &prevDeny)
	facts["prior_approved"] = prevOK
	facts["prior_denied"] = prevDeny
	var bg int
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions WHERE user_id=$1 AND break_glass AND created_at > NOW() - INTERVAL '30 days'`,
		req.RequesterID).Scan(&bg)
	facts["break_glass_30d"] = bg
	return facts, nil
}

func (s *Service) buildBrief(ctx context.Context, cfg Settings, kind string, ref uuid.UUID) error {
	var facts map[string]any
	var err error
	switch kind {
	case BriefJIT:
		facts, err = s.collectJITFacts(ctx, ref)
	case BriefSupervisor:
		facts, err = s.collectSupervisorFacts(ctx, ref)
	case BriefCommand:
		facts, err = s.collectCommandFacts(ctx, ref)
	default:
		facts, err = s.collectJITFacts(ctx, ref)
	}
	if err != nil {
		return err
	}
	lang := s.langOf(cfg)
	brief := compressFacts(facts, lang)
	rt := s.runtimeFor(cfg)
	if !isMockEndpoint(cfg.Endpoint) && cfg.Model != "mock" {
		rawF, _ := json.Marshal(facts)
		sys := `Compress these PAM approval facts into 5-8 short sentences. Do not recommend approve or deny. JSON {"brief":"..."}`
		raw, err := rt.Chat(ctx, cfg, sys, string(rawF))
		if err == nil {
			var parsed struct {
				Brief string `json:"brief"`
			}
			if json.Unmarshal([]byte(extractJSON(raw)), &parsed) == nil && parsed.Brief != "" {
				brief = parsed.Brief
			}
		}
	}
	raw, _ := json.Marshal(facts)
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO ai_briefs (kind, ref_id, status, model, facts, brief, created_at, updated_at)
		VALUES ($1,$2,'ready',$3,$4,$5,NOW(),NOW())
		ON CONFLICT (kind, ref_id) DO UPDATE SET
			status='ready', model=EXCLUDED.model, facts=EXCLUDED.facts, brief=EXCLUDED.brief, updated_at=NOW()`,
		kind, ref, cfg.Model, raw, brief)
	return err
}

func (s *Service) collectSupervisorFacts(ctx context.Context, sessionID uuid.UUID) (map[string]any, error) {
	row, err := s.sess.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"session_id": sessionID.String(),
		"user":       row.Username,
		"asset":      row.AssetName,
		"protocol":   row.Protocol,
		"risk_score": row.RiskScore,
		"risk_factors": knownFactors(row.RiskFactors),
		"waiting_supervisor": row.WaitingSupervisor,
	}, nil
}

func (s *Service) collectCommandFacts(ctx context.Context, opID uuid.UUID) (map[string]any, error) {
	var method, path, object, channel string
	var sessionID uuid.UUID
	err := s.db.Pool.QueryRow(ctx, `
		SELECT session_id, COALESCE(method,''), COALESCE(path,''), COALESCE(object_name,''), COALESCE(channel,'')
		FROM session_op_approvals WHERE id=$1`, opID).Scan(&sessionID, &method, &path, &object, &channel)
	if err != nil {
		return map[string]any{"op_id": opID.String()}, nil
	}
	cmd := strings.TrimSpace(method + " " + path + " " + object)
	facts := map[string]any{
		"op_id": opID.String(), "command": Redact(cmd), "channel": channel, "session_id": sessionID.String(),
	}
	if row, err := s.sess.Get(ctx, sessionID); err == nil {
		facts["user"] = row.Username
		facts["asset"] = row.AssetName
		facts["risk_score"] = row.RiskScore
	}
	return facts, nil
}

func compressFacts(facts map[string]any, lang string) string {
	var b strings.Builder
	if lang == "en" {
		fmt.Fprintf(&b, "Requester %v asks for %v.", facts["requester"], facts["asset"])
		if v, _ := facts["new_asset"].(bool); v {
			b.WriteString(" This asset is new vs 30-day baseline.")
		}
		fmt.Fprintf(&b, " Risk %v. Sessions/30d: %v. Prior deny: %v.", facts["risk_score"], facts["sessions_30d"], facts["prior_denied"])
	} else {
		fmt.Fprintf(&b, "Заявитель %v запрашивает %v.", facts["requester"], facts["asset"])
		if v, _ := facts["new_asset"].(bool); v {
			b.WriteString(" Актив новый относительно 30-дневного профиля.")
		}
		fmt.Fprintf(&b, " Риск %v. Сессий за 30д: %v. Ранее отклонено: %v.", facts["risk_score"], facts["sessions_30d"], facts["prior_denied"])
	}
	if fs, ok := facts["risk_factors"].([]string); ok && len(fs) > 0 {
		fmt.Fprintf(&b, " Факторы: %s.", strings.Join(fs, ", "))
	}
	b.WriteString(" Решение принимает человек; ИИ не рекомендует approve/deny.")
	return b.String()
}

func (s *Service) GetBrief(ctx context.Context, kind string, ref uuid.UUID) (Brief, error) {
	cfg, err := s.Get(ctx)
	if err != nil {
		return Brief{}, err
	}
	var out Brief
	var raw []byte
	err = s.db.Pool.QueryRow(ctx, `
		SELECT kind, ref_id, status, model, facts, brief, updated_at FROM ai_briefs WHERE kind=$1 AND ref_id=$2`,
		kind, ref).Scan(&out.Kind, &out.RefID, &out.Status, &out.Model, &raw, &out.Brief, &out.UpdatedAt)
	if err == pgx.ErrNoRows {
		if err := s.buildBrief(ctx, cfg, kind, ref); err != nil {
			return s.factsBrief(ctx, kind, ref, cfg)
		}
		err = s.db.Pool.QueryRow(ctx, `
			SELECT kind, ref_id, status, model, facts, brief, updated_at FROM ai_briefs WHERE kind=$1 AND ref_id=$2`,
			kind, ref).Scan(&out.Kind, &out.RefID, &out.Status, &out.Model, &raw, &out.Brief, &out.UpdatedAt)
		if err != nil {
			return s.factsBrief(ctx, kind, ref, cfg)
		}
	} else if err != nil {
		return Brief{}, err
	} else {
		_ = json.Unmarshal(raw, &out.Facts)
		if out.Facts == nil {
			out.Facts = map[string]any{}
		}
		return out, nil
	}
	_ = json.Unmarshal(raw, &out.Facts)
	if out.Facts == nil {
		out.Facts = map[string]any{}
	}
	return out, nil
}

func (s *Service) factsBrief(ctx context.Context, kind string, ref uuid.UUID, cfg Settings) (Brief, error) {
	var facts map[string]any
	var err error
	switch kind {
	case BriefSupervisor:
		facts, err = s.collectSupervisorFacts(ctx, ref)
	case BriefCommand:
		facts, err = s.collectCommandFacts(ctx, ref)
	default:
		facts, err = s.collectJITFacts(ctx, ref)
	}
	if err != nil {
		return Brief{}, err
	}
	return Brief{Kind: kind, RefID: ref, Status: "ready", Model: "facts", Facts: facts, Brief: compressFacts(facts, s.langOf(cfg)), UpdatedAt: time.Now().UTC()}, nil
}

func (s *Service) DraftJEA(ctx context.Context, prompt, userID string) (Draft, error) {
	cfg, _ := s.Get(ctx)
	d := parseJEADraft(prompt)
	d.Model = "mock"
	if userID != "" {
		if id, err := uuid.Parse(userID); err == nil {
			rows, err := s.db.Pool.Query(ctx, `
				SELECT DISTINCT COALESCE(payload->>'command', payload->>'statement','')
				FROM session_events e JOIN sessions s ON s.id=e.session_id
				WHERE s.user_id=$1 AND e.event_type IN ('command','sql')
				AND s.created_at > NOW() - INTERVAL '30 days'
				LIMIT 40`, id)
			if err == nil {
				defer rows.Close()
				var extra []string
				for rows.Next() {
					var c string
					if rows.Scan(&c) == nil && strings.TrimSpace(c) != "" {
						extra = append(extra, strings.TrimSpace(c))
					}
				}
				if len(extra) > 0 {
					d.Patterns = append(d.Patterns, extra...)
					d.Notes = append(d.Notes, "Добавлены команды из сессий пользователя за 30 дней.")
				}
			}
		}
	}
	if !isMockEndpoint(cfg.Endpoint) && cfg.Model != "mock" && cfg.Mode != ModeOff {
		rt := s.runtimeFor(cfg)
		raw, err := rt.Chat(ctx, cfg, `Return JSON {"policy":{},"patterns":[],"notes":[]}. Do not invent destructive allows.`, prompt)
		if err == nil {
			var parsed Draft
			if json.Unmarshal([]byte(extractJSON(raw)), &parsed) == nil {
				if len(parsed.Patterns) > 0 {
					d.Patterns = parsed.Patterns
				}
				if parsed.Policy != nil {
					d.Policy = parsed.Policy
				}
				if len(parsed.Notes) > 0 {
					d.Notes = parsed.Notes
				}
				d.Model = cfg.Model
			}
		}
	}
	d.Prompt = prompt
	return d, nil
}

func (s *Service) HelpAsk(ctx context.Context, q string) (HelpAnswer, error) {
	cfg, _ := s.Get(ctx)
	lang := s.langOf(cfg)
	ans := answerHelp(q, lang)
	if !isMockEndpoint(cfg.Endpoint) && cfg.Model != "mock" && cfg.Mode != ModeOff {
		rt := s.runtimeFor(cfg)
		raw, err := rt.Chat(ctx, cfg, "Answer from KeepPAM help. No session data. Short.", q+"\nKnown:\n"+ans.Answer)
		if err == nil && strings.TrimSpace(raw) != "" {
			ans.Answer = strings.TrimSpace(raw)
			ans.Model = cfg.Model
		}
	}
	return ans, nil
}

func extractJSON(raw string) string {
	raw = strings.TrimSpace(raw)
	i := strings.Index(raw, "{")
	j := strings.LastIndex(raw, "}")
	if i >= 0 && j > i {
		return raw[i : j+1]
	}
	return raw
}
