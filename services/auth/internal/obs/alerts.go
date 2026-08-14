package obs

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type AlertEvent struct {
	Status      string
	Name        string
	Severity    string
	Summary     string
	Description string
	Fingerprint string
	StartsAt    time.Time
}

func ParseAlertmanagerWebhook(raw []byte) ([]AlertEvent, error) {
	var payload struct {
		Status string `json:"status"`
		Alerts []struct {
			Status      string            `json:"status"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
			StartsAt    time.Time         `json:"startsAt"`
			Fingerprint string            `json:"fingerprint"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("invalid alertmanager payload")
	}
	out := make([]AlertEvent, 0, len(payload.Alerts))
	for _, a := range payload.Alerts {
		if len(out) >= 20 {
			break
		}
		st := strings.ToLower(strings.TrimSpace(a.Status))
		if st == "" {
			st = strings.ToLower(strings.TrimSpace(payload.Status))
		}
		if st != "firing" && st != "resolved" {
			st = "firing"
		}
		name := strings.TrimSpace(a.Labels["alertname"])
		if name == "" {
			name = "KeepPAMAlert"
		}
		sum := strings.TrimSpace(a.Annotations["summary"])
		if sum == "" {
			sum = name
		}
		desc := strings.TrimSpace(a.Annotations["description"])
		fp := strings.TrimSpace(a.Fingerprint)
		if len(fp) > 64 {
			fp = fp[:64]
		}
		out = append(out, AlertEvent{
			Status:      st,
			Name:        truncate(name, 120),
			Severity:    strings.TrimSpace(a.Labels["severity"]),
			Summary:     truncate(sum, 240),
			Description: truncate(desc, 400),
			Fingerprint: fp,
			StartsAt:    a.StartsAt,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no alerts in payload")
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
