package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

type runtimeClient interface {
	Probe(ctx context.Context, cfg Settings) error
	Chat(ctx context.Context, cfg Settings, system, user string) (string, error)
	Embed(ctx context.Context, cfg Settings, texts []string) ([][]float32, error)
}

type mockRuntime struct{}

func (mockRuntime) Probe(context.Context, Settings) error { return nil }

func (m mockRuntime) Chat(_ context.Context, cfg Settings, _, user string) (string, error) {
	return mockChat(cfg.Lang, user), nil
}

func (mockRuntime) Embed(_ context.Context, _ Settings, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i, t := range texts {
		out[i] = HashEmbed(t)
	}
	return out, nil
}

func mockChat(lang, user string) string {
	low := strings.ToLower(user)
	switch {
	case strings.Contains(low, `"events"`) || strings.Contains(low, "session_id"):
		return "" // caller uses MockSummaryFromEvents
	case strings.Contains(low, "risk_factors") || strings.Contains(low, `"factors"`):
		return ""
	case strings.Contains(low, `"facts"`):
		return ""
	case strings.Contains(low, "dba") || strings.Contains(low, "allowlist") || strings.Contains(low, "jea"):
		return ""
	default:
		if lang == "en" {
			return "On-prem copilot mock: no external model."
		}
		return "On-prem copilot (mock): внешняя модель не вызывалась."
	}
}

type httpRuntime struct {
	hc *http.Client
}

func newHTTPRuntime(timeout time.Duration) *httpRuntime {
	if timeout < 5*time.Second {
		timeout = 90 * time.Second
	}
	return &httpRuntime{hc: &http.Client{Timeout: timeout}}
}

func (h *httpRuntime) Probe(ctx context.Context, cfg Settings) error {
	base := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if base == "" {
		return fmt.Errorf("no_runtime")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/models", nil)
	if err != nil {
		return err
	}
	res, err := h.hc.Do(req)
	if err != nil {
		// llama.cpp / some servers only expose chat
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
		if err2 != nil {
			return err
		}
		res2, err2 := h.hc.Do(req2)
		if err2 != nil {
			return err
		}
		defer res2.Body.Close()
		if res2.StatusCode >= 400 {
			return fmt.Errorf("runtime health %d", res2.StatusCode)
		}
		return nil
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return fmt.Errorf("runtime models %d", res.StatusCode)
	}
	return nil
}

func (h *httpRuntime) Chat(ctx context.Context, cfg Settings, system, user string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	body := map[string]any{
		"model": cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"temperature": 0.1,
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := h.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if res.StatusCode >= 400 {
		return "", fmt.Errorf("chat %d: %s", res.StatusCode, truncateRunes(string(b), 200))
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		return "", fmt.Errorf("chat json: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("empty chat")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

func (h *httpRuntime) Embed(ctx context.Context, cfg Settings, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	model := cfg.EmbedModel
	if model == "" {
		model = cfg.Model
	}
	raw, _ := json.Marshal(map[string]any{"model": model, "input": texts})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/embeddings", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := h.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode >= 400 {
		// fallback: local hash vectors
		out := make([][]float32, len(texts))
		for i, t := range texts {
			out[i] = HashEmbed(t)
		}
		return out, nil
	}
	var parsed struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil || len(parsed.Data) != len(texts) {
		out := make([][]float32, len(texts))
		for i, t := range texts {
			out[i] = HashEmbed(t)
		}
		return out, nil
	}
	out := make([][]float32, len(parsed.Data))
	for i, d := range parsed.Data {
		out[i] = d.Embedding
	}
	return out, nil
}

func isMockEndpoint(ep string) bool {
	ep = strings.ToLower(strings.TrimSpace(ep))
	return ep == "" || strings.HasPrefix(ep, "mock://") || ep == "mock"
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}
