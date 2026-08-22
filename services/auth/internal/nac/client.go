package nac

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

const maxBody = 64 * 1024

type PostureRequest struct {
	Event     string   `json:"event"`
	ClientIP  string   `json:"client_ip"`
	ClientMAC string   `json:"client_mac,omitempty"`
	Devices   []string `json:"devices"`
	UserID    string   `json:"user_id"`
	Username  string   `json:"username"`
	AssetID   string   `json:"asset_id"`
	AssetName string   `json:"asset_name"`
	Protocol  string   `json:"protocol"`
	SessionID string   `json:"session_id,omitempty"`
}

type PostureResponse struct {
	Allowed bool   `json:"allowed"`
	VLAN    string `json:"vlan,omitempty"`
	Policy  string `json:"policy,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func postureURL(base, vendor string) (string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		return "", fmt.Errorf("nac api_url required")
	}
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return "", fmt.Errorf("nac api_url must be http(s)")
	}
	base = strings.TrimRight(base, "/")
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "", "generic":
		return base + "/keeppam/posture", nil
	case "cisco_ise":
		return base + "/ers/config/keeppam/posture", nil
	default:
		return "", fmt.Errorf("unknown nac vendor")
	}
}

func callPosture(ctx context.Context, apiURL, token, vendor string, timeout time.Duration, req PostureRequest) (PostureResponse, error) {
	url, err := postureURL(apiURL, vendor)
	if err != nil {
		return PostureResponse{}, err
	}
	b, err := json.Marshal(req)
	if err != nil {
		return PostureResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return PostureResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(token) != "" {
		httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return PostureResponse{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return PostureResponse{}, err
	}
	if resp.StatusCode >= 400 {
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return PostureResponse{}, fmt.Errorf("nac HTTP %d: %s", resp.StatusCode, msg)
	}
	var out PostureResponse
	if len(data) == 0 {
		return PostureResponse{Allowed: true}, nil
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return PostureResponse{}, fmt.Errorf("nac response: %w", err)
	}
	return out, nil
}
