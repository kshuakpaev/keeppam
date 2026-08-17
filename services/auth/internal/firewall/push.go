package firewall

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (s *Service) PushAWX(ctx context.Context, actorID uuid.UUID, ip, ua string) error {
	cfg, awxEnc, err := s.loadSettings(ctx)
	if err != nil {
		return err
	}
	token, _ := s.awxTokenPlain(awxEnc)
	launchURL := strings.TrimSpace(cfg.AwxLaunchURL)
	if launchURL == "" {
		return fmt.Errorf("awx_launch_url not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, launchURL, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(token) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(token))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.setPushResult(ctx, time.Now().UTC(), err.Error())
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 300 {
		msg := fmt.Sprintf("AWX HTTP %d: %s", resp.StatusCode, string(raw))
		s.setPushResult(ctx, time.Now().UTC(), msg)
		return fmt.Errorf("%s", msg)
	}
	now := time.Now().UTC()
	s.setPushResult(ctx, now, "")
	_ = s.aud.Record(ctx, &actorID, "firewall.awx.pushed", "settings", "firewall", ip, ua, map[string]any{
		"launch_url": launchURL, "status": resp.StatusCode,
	})
	return nil
}

func (s *Service) setPushResult(ctx context.Context, at time.Time, errMsg string) {
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE firewall_settings SET last_push_at=$1, last_push_error=$2, updated_at=$1 WHERE id=1`, at, errMsg)
}

func (s *Service) maybeAutoPush(ctx context.Context, actorID uuid.UUID, ip, ua string) {
	cfg, _, err := s.loadSettings(ctx)
	if err != nil || !cfg.AwxAutoPush || strings.TrimSpace(cfg.AwxLaunchURL) == "" {
		return
	}
	_ = s.PushAWX(ctx, actorID, ip, ua)
}
