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

	"github.com/keeppam/auth/internal/assets"
)

const (
	defaultTokenTTL = 15 * time.Minute
	minTokenTTL     = 60 * time.Second
	maxTokenTTL     = 24 * time.Hour
)

type TokenRequestSpec struct {
	Namespace string
	Name      string
	TTL       time.Duration
	Bound     *BoundRef
}

type TokenRequestResult struct {
	Token     string
	ExpiresAt time.Time
}

func ResolveSA(acc assets.Account) (ns, name string) {
	ns = strings.TrimSpace(acc.K8sSANamespace)
	if ns == "" {
		ns = "default"
	}
	name = strings.TrimSpace(acc.K8sSAName)
	if name == "" {
		name = strings.TrimSpace(acc.Username)
	}
	return ns, name
}

func ClampTokenTTL(sec int) time.Duration {
	d := time.Duration(sec) * time.Second
	if d <= 0 {
		d = defaultTokenTTL
	}
	if d < minTokenTTL {
		d = minTokenTTL
	}
	if d > maxTokenTTL {
		d = maxTokenTTL
	}
	return d
}

// MintEphemeral replaces the vault Bearer with a TokenRequest JWT when enabled.
// Vault secret is never returned. On failure there is no fallback to the vault token.
func MintEphemeral(ctx context.Context, creds assets.TargetCreds, pamUser string) (secret, authMode string, exp time.Time, meta map[string]any, err error) {
	if !creds.Account.TokenRequestEnabled {
		return creds.Secret, "vault_kubeconfig", time.Time{}, nil, nil
	}
	if creds.Account.K8sBindUser && strings.TrimSpace(pamUser) == "" {
		return "", "", time.Time{}, nil, fmt.Errorf("bind-user: PAM username required")
	}
	up, err := BuildUpstream(creds)
	if err != nil {
		return "", "", time.Time{}, nil, err
	}
	ns, name := BindSAName(creds.Account, pamUser)
	spec := TokenRequestSpec{Namespace: ns, Name: name, TTL: ClampTokenTTL(creds.Account.TokenTTLSeconds)}
	if creds.Account.K8sBindUser {
		uid, created, err := EnsureSA(ctx, up, ns, name, pamUser)
		if err != nil {
			return "", "", time.Time{}, nil, err
		}
		spec.Bound = &BoundRef{Kind: "ServiceAccount", APIVersion: "v1", Name: name, UID: uid}
		_ = created
	}
	tr, err := RequestToken(ctx, up, spec)
	if err != nil {
		return "", "", time.Time{}, nil, err
	}
	secret = tr.Token
	if creds.AuthMethod == "kubeconfig" {
		secret = RenderKubeconfig(up.Server.String(), tr.Token)
	}
	meta = map[string]any{
		"token_request":     true,
		"sa_namespace":      ns,
		"sa_name":           name,
		"token_ttl_seconds": int(spec.TTL.Seconds()),
		"token_expires_at":  tr.ExpiresAt.UTC().Format(time.RFC3339),
		"bind_user":         creds.Account.K8sBindUser,
	}
	if spec.Bound != nil {
		meta["bound_kind"] = spec.Bound.Kind
		meta["bound_name"] = spec.Bound.Name
	}
	return secret, "token_request", tr.ExpiresAt, meta, nil
}

func RequestToken(ctx context.Context, up *Upstream, spec TokenRequestSpec) (TokenRequestResult, error) {
	if up == nil || up.Server == nil {
		return TokenRequestResult{}, fmt.Errorf("k8s upstream required")
	}
	ns := strings.TrimSpace(spec.Namespace)
	name := strings.TrimSpace(spec.Name)
	if ns == "" || name == "" {
		return TokenRequestResult{}, fmt.Errorf("serviceaccount namespace and name required")
	}
	ttl := spec.TTL
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	if ttl < minTokenTTL {
		ttl = minTokenTTL
	}
	if ttl > maxTokenTTL {
		ttl = maxTokenTTL
	}
	bodyMap := map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec": map[string]any{
			"expirationSeconds": int64(ttl.Seconds()),
		},
	}
	if spec.Bound != nil && spec.Bound.Name != "" && spec.Bound.UID != "" {
		kind := spec.Bound.Kind
		if kind == "" {
			kind = "Secret"
		}
		apiVer := spec.Bound.APIVersion
		if apiVer == "" {
			apiVer = "v1"
		}
		bodyMap["spec"].(map[string]any)["boundObjectRef"] = map[string]any{
			"kind":       kind,
			"apiVersion": apiVer,
			"name":       spec.Bound.Name,
			"uid":        spec.Bound.UID,
		}
	}
	body, err := json.Marshal(bodyMap)
	if err != nil {
		return TokenRequestResult{}, err
	}
	endpoint := strings.TrimRight(up.Server.String(), "/") + "/api/v1/namespaces/" +
		url.PathEscape(ns) + "/serviceaccounts/" + url.PathEscape(name) + "/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return TokenRequestResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if up.Token != "" {
		req.Header.Set("Authorization", "Bearer "+up.Token)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	if up.Transport != nil {
		client.Transport = up.Transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return TokenRequestResult{}, fmt.Errorf("tokenrequest: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return TokenRequestResult{}, fmt.Errorf("tokenrequest %s: %s", resp.Status, k8sStatusMessage(raw))
	}
	var parsed struct {
		Status struct {
			Token               string `json:"token"`
			ExpirationTimestamp string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return TokenRequestResult{}, fmt.Errorf("tokenrequest: invalid response")
	}
	tok := strings.TrimSpace(parsed.Status.Token)
	if tok == "" {
		return TokenRequestResult{}, fmt.Errorf("tokenrequest: empty token")
	}
	exp := time.Now().UTC().Add(ttl)
	if ts := strings.TrimSpace(parsed.Status.ExpirationTimestamp); ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			exp = t.UTC()
		} else if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			exp = t.UTC()
		}
	}
	return TokenRequestResult{Token: tok, ExpiresAt: exp}, nil
}

func k8sStatusMessage(raw []byte) string {
	var st struct {
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &st); err == nil {
		msg := strings.TrimSpace(st.Message)
		if msg == "" {
			msg = strings.TrimSpace(st.Reason)
		}
		if msg != "" {
			return msg
		}
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 240 {
		s = s[:240]
	}
	if s == "" {
		return "error"
	}
	return s
}
