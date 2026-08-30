package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/keeppam/auth/internal/sessionsvc"
)

var summaryTypes = map[string]bool{
	"command": true, "command_denied": true, "command_approval": true, "command_approved": true,
	"sql": true, "sql_denied": true, "file_transfer": true, "win_process": true,
	"dlp": true, "ueba": true, "risk": true, "screen_text": true, "output": true,
}

func eventsHash(evs []indexEvent) string {
	h := sha256.New()
	for _, e := range evs {
		fmt.Fprintf(h, "%s:%s:", e.ID.String(), e.Type)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func snippetOf(typ string, payload map[string]any) string {
	s := sessionsvc.EventSnippet(typ, payload)
	return Redact(s)
}

func eventOffset(p map[string]any) float64 {
	if p == nil {
		return 0
	}
	switch v := p["offset"].(type) {
	case float64:
		return v
	case json.Number:
		f, _ := v.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	}
	return 0
}

func payloadKind(p map[string]any) string {
	if p == nil {
		return ""
	}
	if k, ok := p["kind"].(string); ok {
		return k
	}
	if ks, ok := p["kinds"].([]any); ok && len(ks) > 0 {
		if s, ok := ks[0].(string); ok {
			return s
		}
	}
	return ""
}

// MockSummaryFromEvents builds a grounded summary (no LLM). Used by mock runtime and as fallback.
func MockSummaryFromEvents(sessionID uuid.UUID, proto, user, asset string, score int, factors []string, evs []indexEvent, lang string) Summary {
	var bullets []Bullet
	var notes []RiskNote
	var offsets []OffsetRef
	var screens []string
	seenScreen := map[string]struct{}{}
	denied := 0
	cmds := 0
	sqlN := 0
	files := 0
	for _, e := range evs {
		sn := e.Snippet
		if sn == "" {
			sn = snippetOf(e.Type, e.Payload)
		}
		sn = truncateRunes(strings.TrimSpace(sn), 180)
		if sn == "" {
			continue
		}
		id := e.ID
		off := e.Offset
		b := Bullet{Text: sn, EventID: &id, Type: e.Type, Kind: payloadKind(e.Payload)}
		if off > 0 {
			o := off
			b.Offset = &o
			offsets = append(offsets, OffsetRef{Label: truncateRunes(sn, 80), Offset: off})
		}
		switch e.Type {
		case "command_denied", "sql_denied":
			denied++
			b.Kind = "denied"
			notes = append(notes, RiskNote{EventID: &id, Kind: e.Type, Text: sn})
			bullets = append(bullets, b)
		case "command", "command_approved":
			cmds++
			bullets = append(bullets, b)
		case "sql":
			sqlN++
			bullets = append(bullets, b)
		case "file_transfer":
			files++
			bullets = append(bullets, b)
		case "dlp", "ueba", "risk":
			notes = append(notes, RiskNote{EventID: &id, Kind: e.Type, Text: sn})
			bullets = append(bullets, b)
		case "win_process", "screen_text":
			key := strings.ToLower(sn)
			if _, ok := seenScreen[key]; ok {
				continue
			}
			seenScreen[key] = struct{}{}
			screens = append(screens, sn)
			bullets = append(bullets, b)
		}
		if len(bullets) >= 24 {
			break
		}
	}
	headline := fmt.Sprintf("%s · %s · %s", user, asset, proto)
	if denied > 0 {
		headline += fmt.Sprintf(" · deny×%d", denied)
	}
	var parts []string
	if lang == "en" {
		parts = append(parts, fmt.Sprintf("Session on %s (%s) by %s, risk %d.", asset, proto, user, score))
		if cmds > 0 {
			parts = append(parts, fmt.Sprintf("%d command(s).", cmds))
		}
		if sqlN > 0 {
			parts = append(parts, fmt.Sprintf("%d SQL statement(s).", sqlN))
		}
		if files > 0 {
			parts = append(parts, fmt.Sprintf("%d file transfer(s).", files))
		}
		if denied > 0 {
			parts = append(parts, fmt.Sprintf("%d denied operation(s).", denied))
		}
	} else {
		parts = append(parts, fmt.Sprintf("Сессия на %s (%s), пользователь %s, риск %d.", asset, proto, user, score))
		if cmds > 0 {
			parts = append(parts, fmt.Sprintf("Команд: %d.", cmds))
		}
		if sqlN > 0 {
			parts = append(parts, fmt.Sprintf("SQL: %d.", sqlN))
		}
		if files > 0 {
			parts = append(parts, fmt.Sprintf("Передач файлов: %d.", files))
		}
		if denied > 0 {
			parts = append(parts, fmt.Sprintf("Отклонено операций: %d.", denied))
		}
	}
	if len(factors) > 0 {
		parts = append(parts, "Факторы: "+strings.Join(factors, ", ")+".")
	}
	narr := strings.Join(screens, "; ")
	sum := Summary{
		SessionID:       sessionID,
		Status:          "ready",
		Model:           "mock",
		Headline:        truncateRunes(headline, 200),
		Summary:         strings.Join(parts, " "),
		ScreenNarrative: truncateRunes(narr, 500),
		Bullets:         bullets,
		RiskNotes:       notes,
		Offsets:         offsets,
	}
	return sum
}

func parseSummaryJSON(raw string, fallback Summary) (Summary, error) {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "{"); i >= 0 {
		if j := strings.LastIndex(raw, "}"); j > i {
			raw = raw[i : j+1]
		}
	}
	if raw == "" {
		return fallback, nil
	}
	var parsed struct {
		Headline        string `json:"headline"`
		Summary         string `json:"summary"`
		ScreenNarrative string `json:"screen_narrative"`
		Bullets         []struct {
			Text    string  `json:"text"`
			EventID string  `json:"event_id"`
			Offset  float64 `json:"offset"`
			Kind    string  `json:"kind"`
			Type    string  `json:"type"`
		} `json:"bullets"`
		RiskNotes []struct {
			Text    string `json:"text"`
			EventID string `json:"event_id"`
			Kind    string `json:"kind"`
		} `json:"risk_notes"`
		Offsets []OffsetRef `json:"offsets"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return Summary{}, fmt.Errorf("summary json: %w", err)
	}
	out := fallback
	if parsed.Headline != "" {
		out.Headline = truncateRunes(parsed.Headline, 200)
	}
	if parsed.Summary != "" {
		out.Summary = parsed.Summary
	}
	if parsed.ScreenNarrative != "" {
		out.ScreenNarrative = parsed.ScreenNarrative
	}
	allowed := map[string]indexEvent{}
	// fallback bullets carry allowed event ids
	for _, b := range fallback.Bullets {
		if b.EventID != nil {
			allowed[b.EventID.String()] = indexEvent{}
		}
	}
	if len(parsed.Bullets) > 0 {
		var bullets []Bullet
		for _, b := range parsed.Bullets {
			id, err := uuid.Parse(strings.TrimSpace(b.EventID))
			if err != nil || b.Text == "" {
				continue
			}
			if _, ok := allowed[id.String()]; !ok && len(allowed) > 0 {
				continue
			}
			bb := Bullet{Text: truncateRunes(b.Text, 240), EventID: &id, Kind: b.Kind, Type: b.Type}
			if b.Offset > 0 {
				o := b.Offset
				bb.Offset = &o
			}
			bullets = append(bullets, bb)
		}
		if len(bullets) > 0 {
			out.Bullets = bullets
		}
	}
	if len(parsed.RiskNotes) > 0 {
		var notes []RiskNote
		for _, n := range parsed.RiskNotes {
			nn := RiskNote{Kind: n.Kind, Text: truncateRunes(n.Text, 240)}
			if id, err := uuid.Parse(n.EventID); err == nil {
				nn.EventID = &id
			}
			notes = append(notes, nn)
		}
		out.RiskNotes = notes
	}
	if len(parsed.Offsets) > 0 {
		out.Offsets = parsed.Offsets
	}
	out.Status = "ready"
	return out, nil
}
