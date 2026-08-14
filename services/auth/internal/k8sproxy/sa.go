package k8sproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
)

type BoundRef struct {
	Kind       string
	APIVersion string
	Name       string
	UID        string
}

func DNS1123(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if unicode.IsLetter(r) {
			continue
		}
		if b.Len() > 0 && !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "user"
	}
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	return out
}

func BindSAName(acc assets.Account, pamUser string) (ns, name string) {
	ns, name = ResolveSA(acc)
	if !acc.K8sBindUser {
		return ns, name
	}
	user := DNS1123(pamUser)
	if strings.TrimSpace(acc.K8sSAName) != "" {
		name = DNS1123(acc.K8sSAName + "-" + user)
	} else {
		name = DNS1123("keeppam-" + user)
	}
	return ns, name
}

func BindSecretName(sessionID uuid.UUID) string {
	return "kp-" + strings.ReplaceAll(sessionID.String(), "-", "")
}

func k8sJSON(ctx context.Context, up *Upstream, method, path string, body any) (int, []byte, error) {
	if up == nil || up.Server == nil {
		return 0, nil, fmt.Errorf("k8s upstream required")
	}
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(raw)
	}
	endpoint := strings.TrimRight(up.Server.String(), "/") + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if up.Token != "" {
		req.Header.Set("Authorization", "Bearer "+up.Token)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	if up.Transport != nil {
		client.Transport = up.Transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, nil
}

func objectUID(raw []byte) string {
	var obj struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(raw, &obj)
	return strings.TrimSpace(obj.Metadata.UID)
}

func EnsureSA(ctx context.Context, up *Upstream, ns, name, pamUser string) (uid string, created bool, err error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return "", false, fmt.Errorf("serviceaccount namespace and name required")
	}
	path := "/api/v1/namespaces/" + url.PathEscape(ns) + "/serviceaccounts/" + url.PathEscape(name)
	code, raw, err := k8sJSON(ctx, up, http.MethodGet, path, nil)
	if err != nil {
		return "", false, fmt.Errorf("get sa: %w", err)
	}
	if code >= 200 && code < 300 {
		uid = objectUID(raw)
		if uid == "" {
			return "", false, fmt.Errorf("serviceaccount %s/%s: empty uid", ns, name)
		}
		return uid, false, nil
	}
	if code != http.StatusNotFound {
		return "", false, fmt.Errorf("get sa %s: %s", http.StatusText(code), k8sStatusMessage(raw))
	}
	body := map[string]any{
		"apiVersion": "v1",
		"kind":       "ServiceAccount",
		"metadata": map[string]any{
			"name": name,
			"labels": map[string]string{
				"app.kubernetes.io/managed-by": "keeppam",
				"keeppam.io/user":              DNS1123(pamUser),
			},
		},
	}
	code, raw, err = k8sJSON(ctx, up, http.MethodPost, "/api/v1/namespaces/"+url.PathEscape(ns)+"/serviceaccounts", body)
	if err != nil {
		return "", false, fmt.Errorf("create sa: %w", err)
	}
	if code == http.StatusConflict {
		code, raw, err = k8sJSON(ctx, up, http.MethodGet, path, nil)
		if err != nil {
			return "", false, err
		}
		if code >= 200 && code < 300 {
			uid = objectUID(raw)
			if uid == "" {
				return "", false, fmt.Errorf("serviceaccount %s/%s: empty uid", ns, name)
			}
			return uid, false, nil
		}
	}
	if code < 200 || code >= 300 {
		return "", false, fmt.Errorf("create sa %s: %s", http.StatusText(code), k8sStatusMessage(raw))
	}
	uid = objectUID(raw)
	if uid == "" {
		return "", false, fmt.Errorf("create sa %s/%s: empty uid", ns, name)
	}
	return uid, true, nil
}

func EnsureBindSecret(ctx context.Context, up *Upstream, ns, name, sessionID string) (uid string, err error) {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return "", fmt.Errorf("bind secret namespace and name required")
	}
	path := "/api/v1/namespaces/" + url.PathEscape(ns) + "/secrets/" + url.PathEscape(name)
	code, raw, err := k8sJSON(ctx, up, http.MethodGet, path, nil)
	if err != nil {
		return "", fmt.Errorf("get secret: %w", err)
	}
	if code >= 200 && code < 300 {
		uid = objectUID(raw)
		if uid == "" {
			return "", fmt.Errorf("secret %s/%s: empty uid", ns, name)
		}
		return uid, nil
	}
	if code != http.StatusNotFound {
		return "", fmt.Errorf("get secret %s: %s", http.StatusText(code), k8sStatusMessage(raw))
	}
	labels := map[string]string{"app.kubernetes.io/managed-by": "keeppam"}
	if sessionID != "" {
		labels["keeppam.io/session"] = DNS1123(sessionID)
	}
	body := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":   name,
			"labels": labels,
		},
		"type": "Opaque",
	}
	code, raw, err = k8sJSON(ctx, up, http.MethodPost, "/api/v1/namespaces/"+url.PathEscape(ns)+"/secrets", body)
	if err != nil {
		return "", fmt.Errorf("create secret: %w", err)
	}
	if code == http.StatusConflict {
		code, raw, err = k8sJSON(ctx, up, http.MethodGet, path, nil)
		if err != nil {
			return "", err
		}
		if code >= 200 && code < 300 {
			uid = objectUID(raw)
			if uid == "" {
				return "", fmt.Errorf("secret %s/%s: empty uid", ns, name)
			}
			return uid, nil
		}
	}
	if code < 200 || code >= 300 {
		return "", fmt.Errorf("create secret %s: %s", http.StatusText(code), k8sStatusMessage(raw))
	}
	uid = objectUID(raw)
	if uid == "" {
		return "", fmt.Errorf("create secret %s/%s: empty uid", ns, name)
	}
	return uid, nil
}

func DeleteBindSecret(ctx context.Context, up *Upstream, ns, name string) error {
	ns = strings.TrimSpace(ns)
	name = strings.TrimSpace(name)
	if ns == "" || name == "" {
		return nil
	}
	path := "/api/v1/namespaces/" + url.PathEscape(ns) + "/secrets/" + url.PathEscape(name)
	code, raw, err := k8sJSON(ctx, up, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	if code == http.StatusNotFound || (code >= 200 && code < 300) {
		return nil
	}
	return fmt.Errorf("delete secret %s: %s", http.StatusText(code), k8sStatusMessage(raw))
}
