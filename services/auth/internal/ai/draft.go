package ai

import (
	"strings"
)

func parseJEADraft(prompt string) Draft {
	p := strings.ToLower(prompt)
	d := Draft{
		Prompt: prompt,
		Policy: map[string]any{
			"name":       "ai-draft",
			"max_risk":   40,
			"risk_action": "deny",
		},
		Notes: []string{"Черновик. Сохранение только вручную. Live deny по-прежнему glob + парсер."},
		Model: "mock",
	}
	var patterns []string
	if strings.Contains(p, "rm") || strings.Contains(p, "dd") || strings.Contains(p, "без rm") {
		patterns = append(patterns, "rm *", "dd", "mkfs *")
		d.Policy["command_mode"] = "denylist"
		d.Notes = append(d.Notes, "В denylist: rm, dd, mkfs.")
	}
	if strings.Contains(p, "dba") || strings.Contains(p, "*db*") {
		d.Policy["asset_match"] = "*db*"
		d.Notes = append(d.Notes, "Фильтр активов *db*.")
	}
	if strings.Contains(p, "пн") || strings.Contains(p, "9–18") || strings.Contains(p, "9-18") || strings.Contains(p, "week") {
		d.Policy["hours"] = map[string]string{"from": "09:00", "to": "18:00"}
		d.Policy["weekdays"] = []string{"mon", "tue", "wed", "thu", "fri"}
	}
	if strings.Contains(p, "ssh") {
		d.Policy["protocols"] = []string{"ssh"}
	}
	if len(patterns) == 0 {
		patterns = []string{"sudo *", "systemctl *", "journalctl *"}
		d.Policy["command_mode"] = "allowlist"
		d.Notes = append(d.Notes, "Пустой запрет — предложен узкий allowlist для правки.")
	}
	d.Patterns = patterns
	return d
}

func parseDraftJSON(raw string, fallback Draft) Draft {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "{"); i >= 0 {
		if j := strings.LastIndex(raw, "}"); j > i {
			raw = raw[i : j+1]
		}
	}
	if raw == "" {
		return fallback
	}
	// keep fallback if parse fails — caller unmarshals optionally
	return fallback
}
