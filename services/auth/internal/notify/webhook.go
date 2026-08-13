package notify

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

func PostJSON(ctx context.Context, rawURL, authHeader string, timeout time.Duration, payload any) error {
	if strings.TrimSpace(rawURL) == "" {
		return fmt.Errorf("webhook_url required")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "KeepPAM-Notify/1.0")
	if authHeader != "" {
		if strings.Contains(authHeader, ":") {
			parts := strings.SplitN(authHeader, ":", 2)
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		} else {
			req.Header.Set("Authorization", authHeader)
		}
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}
