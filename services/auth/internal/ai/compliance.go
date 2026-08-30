package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/keeppam/auth/internal/compliance"
)

func proseFromSummary(sum compliance.ReportSummary, lang string) string {
	if lang == "en" {
		return fmt.Sprintf(
			"Period totals (AI narrative, not evidence): access grants %d; privileged/break-glass %d; approvals %d; connections %d; commands %d; SQL %d; downloads %d; changes %d; revocations %d.",
			sum.Access, sum.Privileged, sum.Approvals, sum.Connections, sum.Commands, sum.SQL, sum.Downloads, sum.Changes, sum.Revoked,
		)
	}
	return fmt.Sprintf(
		"Итоги за период (проза ИИ, не доказательство): выдач доступа %d; привилегированных/break-glass %d; согласований %d; подключений %d; команд %d; SQL %d; выгрузок %d; изменений %d; отзывов %d.",
		sum.Access, sum.Privileged, sum.Approvals, sum.Connections, sum.Commands, sum.SQL, sum.Downloads, sum.Changes, sum.Revoked,
	)
}

func (s *Service) ComplianceProse(ctx context.Context, sum compliance.ReportSummary) string {
	cfg, _ := s.Get(ctx)
	lang := s.langOf(cfg)
	text := proseFromSummary(sum, lang)
	if !isMockEndpoint(cfg.Endpoint) && cfg.Model != "mock" && cfg.Mode != ModeOff {
		rt := s.runtimeFor(cfg)
		payload := proseFromSummary(sum, "en")
		raw, err := rt.Chat(ctx, cfg, "Rewrite as 1-2 auditor paragraphs. Keep every number unchanged. JSON {\"prose\":\"...\"}", payload)
		if err == nil {
			var parsed struct {
				Prose string `json:"prose"`
			}
			if json.Unmarshal([]byte(extractJSON(raw)), &parsed) == nil && parsed.Prose != "" {
				text = parsed.Prose
			}
		}
	}
	if !numbersOK(text, sum) {
		return ""
	}
	return text
}

func numbersOK(prose string, sum compliance.ReportSummary) bool {
	vals := []int{sum.Access, sum.Privileged, sum.Approvals, sum.Connections, sum.Commands, sum.SQL, sum.Downloads, sum.Changes, sum.Revoked}
	for _, v := range vals {
		if v == 0 {
			continue
		}
		if !strings.Contains(prose, strconv.Itoa(v)) {
			return false
		}
	}
	return true
}
