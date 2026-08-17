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
)

const ocrMaxFrames = 20

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

func (s *Service) fetchOCR(ctx context.Context, guacPath string) ([]ocrFrame, error) {
	if s == nil || strings.TrimSpace(s.guacencURL) == "" {
		return nil, fmt.Errorf("guacenc not configured")
	}
	body, _ := json.Marshal(map[string]any{"path": guacPath, "max_frames": ocrMaxFrames})
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
