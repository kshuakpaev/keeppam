package ai

import (
	"fmt"
	"strings"
)

type helpTopic struct {
	ID      string
	TitleRU string
	TitleEN string
	BodyRU  string
	BodyEN  string
}

var helpCorpus = []helpTopic{
	{ID: "overview", TitleRU: "Обзор", TitleEN: "Overview",
		BodyRU: "Домашняя страница PAM: активные сессии, аномалии, неудачные входы.",
		BodyEN: "Home dashboard: active sessions, anomalies, failed logins."},
	{ID: "sessions", TitleRU: "Сессии", TitleEN: "Sessions",
		BodyRU: "Запись SSH/RDP, replay, kill, forensic-поиск по session_events.",
		BodyEN: "SSH/RDP recording, replay, kill, forensic search over session_events."},
	{ID: "jit", TitleRU: "JIT", TitleEN: "JIT",
		BodyRU: "Just-in-Time доступ: этапы руководитель→ИБ или кворум N из M. Свою заявку одобрить нельзя.",
		BodyEN: "Just-in-Time access: manager then security, or N-of-M quorum. You cannot approve your own request."},
	{ID: "supervisor", TitleRU: "Четыре глаза", TitleEN: "Four eyes",
		BodyRU: "Супервайзер сессии одобряет connect до Dial/Guac. Таймаут 15 мин.",
		BodyEN: "Session supervisor must approve connect before Dial/Guac. 15 min timeout."},
	{ID: "ueba", TitleRU: "UEBA", TitleEN: "UEBA",
		BodyRU: "Профиль активов за 30 дней, скорость клавиш/мыши, peer-group ML score. Не нейросеть.",
		BodyEN: "30-day asset profile, keystroke/mouse speed, peer-group ML score. Not a neural net."},
	{ID: "dlp", TitleRU: "DLP", TitleEN: "DLP",
		BodyRU: "PII regex и NLP-keywords: audit/mask/deny. Не BERT. ИИ-сводка не меняет deny.",
		BodyEN: "PII regex and NLP keywords: audit/mask/deny. Not BERT. AI summary does not change deny."},
	{ID: "ai", TitleRU: "ИИ-помощник", TitleEN: "AI copilot",
		BodyRU: "On-prem сводка сессии и поиск по смыслу. Нет пункта ИИ в меню: Конфигурация → ИИ-помощник (режим on). Сводка — Replay; поиск — Сессии «По смыслу»; контекст — Запросы; черновик — JEA; вопрос — Справка; проза — Compliance; риск — Аналитика. Не в live deny и не автоapprove.",
		BodyEN: "On-prem session summary and semantic search. No AI sidebar item: Configuration → AI copilot (mode on). Summary in Replay; search on Sessions; context on Requests; draft on JEA; ask on Help; prose on Compliance; risk on Analytics. Not in live deny, never auto-approve."},
}

func answerHelp(q, lang string) HelpAnswer {
	q = strings.TrimSpace(q)
	low := strings.ToLower(q)
	var hits []helpTopic
	for _, t := range helpCorpus {
		hay := strings.ToLower(t.ID + " " + t.TitleRU + " " + t.TitleEN + " " + t.BodyRU + " " + t.BodyEN)
		score := 0
		for _, w := range strings.Fields(low) {
			if len(w) < 2 {
				continue
			}
			if strings.Contains(hay, w) {
				score++
			}
		}
		if score > 0 {
			hits = append(hits, t)
		}
	}
	out := HelpAnswer{Question: q, Model: "mock"}
	if len(hits) == 0 {
		if lang == "en" {
			out.Answer = "No matching help topic. Try Sessions, JIT, UEBA, DLP."
		} else {
			out.Answer = "Тема не найдена. Попробуйте: сессии, JIT, UEBA, DLP."
		}
		return out
	}
	var b strings.Builder
	for i, t := range hits {
		if i >= 3 {
			break
		}
		out.Topics = append(out.Topics, t.ID)
		title, body := t.TitleRU, t.BodyRU
		if lang == "en" {
			title, body = t.TitleEN, t.BodyEN
		}
		fmt.Fprintf(&b, "%s. %s\n", title, body)
	}
	out.Answer = strings.TrimSpace(b.String())
	return out
}
