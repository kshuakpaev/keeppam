package hdx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to an OEM HDX terminate plugin over HTTP (SOW-CITRIX-HDX phase 3).
// KeepPAM never decodes HDX itself — the plugin owns the protocol stack.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func NewClient(baseURL string) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" || baseURL == "off" {
		return nil
	}
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) Enabled() bool { return c != nil && c.BaseURL != "" }

type Health struct {
	Status       string   `json:"status"`
	Capabilities []string `json:"capabilities"`
	Vendor       string   `json:"vendor,omitempty"`
	Version      string   `json:"version,omitempty"`
}

func (c *Client) Health(ctx context.Context) (Health, error) {
	var h Health
	if err := c.get(ctx, "/healthz", &h); err != nil {
		return h, err
	}
	if h.Status == "" {
		h.Status = "ok"
	}
	return h, nil
}

type StartRequest struct {
	KeepPAMSessionID string `json:"keeppam_session_id"`
	VDAHost          string `json:"vda_host"`
	VDAPort          int    `json:"vda_port"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	InitialProgram   string `json:"initial_program,omitempty"`
	STATicket        string `json:"sta_ticket,omitempty"`
	StoreFrontURL    string `json:"storefront_url,omitempty"`
	TTLSeconds       int    `json:"ttl_seconds,omitempty"`
	RecordingHint    string `json:"recording_hint,omitempty"`
	CallbackURL      string `json:"callback_url,omitempty"`
	IngestToken      string `json:"ingest_token,omitempty"`
	Record           bool   `json:"record,omitempty"`
}

type StartResponse struct {
	PluginSessionID string `json:"plugin_session_id"`
	Status          string `json:"status"`
	ListenAddr      string `json:"listen_addr,omitempty"`
	Mode            string `json:"mode"` // terminate
	Message         string `json:"message,omitempty"`
}

type StatusResponse struct {
	PluginSessionID string         `json:"plugin_session_id"`
	Status          string         `json:"status"`
	Events          []RecordingEvt `json:"events,omitempty"`
}

type RecordingEvt struct {
	T     string         `json:"t"`
	Event string         `json:"event"`
	Seq   int            `json:"seq,omitempty"`
	Meta  map[string]any `json:"meta,omitempty"`
}

type IngestRequest struct {
	Events []RecordingEvt `json:"events"`
}

func (c *Client) Start(ctx context.Context, req StartRequest) (StartResponse, error) {
	var out StartResponse
	if err := c.post(ctx, "/v1/sessions", req, &out); err != nil {
		return out, err
	}
	if out.PluginSessionID == "" {
		return out, fmt.Errorf("plugin returned empty session id")
	}
	if out.Mode == "" {
		out.Mode = "terminate"
	}
	return out, nil
}

func (c *Client) Status(ctx context.Context, pluginSessionID string) (StatusResponse, error) {
	var out StatusResponse
	err := c.get(ctx, "/v1/sessions/"+pluginSessionID, &out)
	return out, err
}

func (c *Client) Stop(ctx context.Context, pluginSessionID string) error {
	return c.do(ctx, http.MethodDelete, "/v1/sessions/"+pluginSessionID, nil, nil)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	return c.do(ctx, http.MethodPost, path, in, out)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	if !c.Enabled() {
		return fmt.Errorf("hdx plugin not configured")
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("hdx plugin HTTP %d: %s", res.StatusCode, truncate(string(b), 200))
	}
	if out == nil || len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, out)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
