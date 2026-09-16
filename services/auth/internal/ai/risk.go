package ai

import (
	"fmt"
	"strings"
)

// Known risk factor codes. Unknown codes are dropped from model output (P4 DoD).
var factorDict = map[string]struct{ RU, EN string }{
	"ueba_new_asset":      {RU: "новый актив вне 30-дневного профиля", EN: "asset not in 30-day baseline"},
	"ueba_new_ip":         {RU: "подключение с нового IP вне 30-дневного профиля", EN: "source IP not in 30-day baseline"},
	"ueba_new_subnet":     {RU: "подключение из новой подсети вне 30-дневного профиля", EN: "source subnet not in 30-day baseline"},
	"ueba_spread":         {RU: "резкий рост числа уникальных активов за сутки", EN: "sudden spread across many assets"},
	"ueba_unusual_hour":   {RU: "вход в час, которого не было в 30-дневном профиле", EN: "login hour absent from 30-day profile"},
	"ueba_keystroke_fast": {RU: "аномально быстрый ввод с клавиатуры", EN: "anomalously fast typing"},
	"ueba_mouse_fast":     {RU: "аномально быстрое движение мыши", EN: "anomalously fast mouse"},
	"ueba_peer_outlier":   {RU: "актив редко посещают коллеги по группе", EN: "asset rarely used by peer group"},
	"ueba_ml_high":        {RU: "составной UEBA-ML балл выше порога", EN: "composite UEBA-ML score above threshold"},
	"ueba_live_fast":      {RU: "live mid-session: bot-like клавиши/мышь", EN: "live mid-session bot-like input"},
	"off_hours":           {RU: "подключение вне рабочих часов", EN: "connection outside business hours"},
	"geo_mismatch":        {RU: "страна клиента не совпадает с обычной", EN: "client country differs from usual"},
	"new_country":         {RU: "вход из новой страны", EN: "login from a new country"},
	"failed_logins":       {RU: "недавние неудачные входы", EN: "recent failed logins"},
	"break_glass":         {RU: "сессия через break-glass", EN: "break-glass session"},
	"admin_bypass":        {RU: "обход ACL администратором", EN: "admin ACL bypass"},
	"step_up":             {RU: "требовался step-up MFA", EN: "step-up MFA was required"},
}

func knownFactors(in []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, f := range in {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if _, ok := factorDict[f]; !ok {
			continue
		}
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	return out
}

func explainFactors(factors []string, score int, lang string) string {
	factors = knownFactors(factors)
	if len(factors) == 0 {
		if lang == "en" {
			return fmt.Sprintf("Connect risk score %d has no named UEBA/ABAC factors.", score)
		}
		return fmt.Sprintf("Балл риска на connect: %d. Именованных факторов UEBA/ABAC нет.", score)
	}
	var lines []string
	if lang == "en" {
		lines = append(lines, fmt.Sprintf("Risk score %d. Why this session was scored:", score))
	} else {
		lines = append(lines, fmt.Sprintf("Балл риска %d. Почему сессия получила оценку:", score))
	}
	for _, f := range factors {
		d := factorDict[f]
		label := d.RU
		if lang == "en" {
			label = d.EN
		}
		lines = append(lines, fmt.Sprintf("• %s — %s.", f, label))
	}
	return strings.Join(lines, "\n")
}

func filterExplainText(text string, factors []string) string {
	factors = knownFactors(factors)
	if text == "" {
		return text
	}
	allowed := map[string]struct{}{}
	for _, f := range factors {
		allowed[f] = struct{}{}
	}
	var keep []string
	for _, line := range strings.Split(text, "\n") {
		ok := true
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == ',' || r == '.' || r == ';' || r == ':' || r == '—' || r == '-'
		}) {
			if strings.Contains(tok, "_") && len(tok) > 4 {
				if _, allow := allowed[tok]; allow {
					continue
				}
				ok = false
				break
			}
		}
		if ok {
			keep = append(keep, line)
		}
	}
	return strings.TrimSpace(strings.Join(keep, "\n"))
}
