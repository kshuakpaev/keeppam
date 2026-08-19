package castindex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/keeppam/auth/internal/policy"
)

type ocrFrame struct {
	Offset float64 `json:"offset"`
	Text   string  `json:"text"`
}

type ocrResponse struct {
	Status string     `json:"status"`
	Error  string     `json:"error"`
	Detail string     `json:"detail"`
	Frames []ocrFrame `json:"frames"`
}

func (s *Service) fetchOCR(ctx context.Context, guacPath string, opt policy.OCROpts) ([]ocrFrame, error) {
	if s == nil || strings.TrimSpace(s.guacencURL) == "" {
		return nil, fmt.Errorf("guacenc not configured")
	}
	if opt.Lang == "" {
		opt.Lang = policy.OCRDefaultLang
	}
	if opt.IntervalSec <= 0 {
		opt.IntervalSec = policy.OCRDefaultInterval
	}
	if opt.MaxFrames <= 0 {
		opt.MaxFrames = policy.OCRDefaultFrames
	}
	if opt.MaxFrames > policy.OCRMaxFramesCap {
		opt.MaxFrames = policy.OCRMaxFramesCap
	}
	body, _ := json.Marshal(map[string]any{
		"path": guacPath, "max_frames": opt.MaxFrames,
		"interval_sec": opt.IntervalSec, "lang": opt.Lang,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.guacencURL, "/")+"/ocr", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Minute}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	var out ocrResponse
	_ = json.Unmarshal(raw, &out)
	if res.StatusCode >= 300 {
		msg := out.Error
		if msg == "" {
			msg = string(raw)
		}
		if out.Detail != "" {
			msg = msg + ": " + out.Detail
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return out.Frames, nil
}
