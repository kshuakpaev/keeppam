package k8sproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/sessionsvc"
)

type CallOptions struct {
	Method      string
	Path        string
	Body        []byte
	ContentType string
	AllowExec   bool   // pods/exec (legacy)
	AllowSub    string // exec | attach | portforward
}

func (g *Gateway) Call(ctx context.Context, row sessionsvc.Session, method, path string) (int, []byte, error) {
	return g.Do(ctx, row, CallOptions{Method: method, Path: path})
}

func (g *Gateway) Do(ctx context.Context, row sessionsvc.Session, opt CallOptions) (int, []byte, error) {
	up, call, err := g.prepareBrowser(ctx, row, opt)
	if err != nil {
		if syn, ok := err.(errSynthetic); ok {
			return http.StatusOK, syn.body, nil
		}
		return statusFromErr(err), nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(opt.Method))
	if method == "" {
		method = http.MethodGet
	}
	endpoint := strings.TrimRight(up.up.Server.String(), "/") + opt.Path
	var rdr io.Reader
	if len(opt.Body) > 0 {
		rdr = bytes.NewReader(opt.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if len(opt.Body) > 0 {
		ct := opt.ContentType
		if ct == "" {
			ct = "application/json"
		}
		req.Header.Set("Content-Type", ct)
	}
	applyUpstreamAuth(req.Header, up)
	client := httpClient(up.up, 25*time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("upstream: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if strings.EqualFold(call.Resource, "secrets") {
		raw = RedactSecretJSON(raw)
	}
	g.noteCall(ctx, row, call, method, opt.Path, resp.StatusCode)
	return resp.StatusCode, raw, nil
}

func (g *Gateway) prepareBrowser(ctx context.Context, row sessionsvc.Session, opt CallOptions) (*sessionUpstream, APICall, error) {
	if g == nil {
		return nil, APICall{}, fmt.Errorf("k8s gateway disabled")
	}
	if row.Protocol != "kubectl" {
		return nil, APICall{}, fmt.Errorf("not a kubectl session")
	}
	if row.Status != "pending" && row.Status != "active" {
		return nil, APICall{}, fmt.Errorf("session not active")
	}
	method := strings.ToUpper(strings.TrimSpace(opt.Method))
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return nil, APICall{}, errStatus(http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", method))
	}
	path := opt.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	call := ParseAPIPath(method, path, false)
	allow := strings.ToLower(strings.TrimSpace(opt.AllowSub))
	if opt.AllowExec && allow == "" {
		allow = "exec"
	}
	if allow != "" {
		if err := allowPodSubresource(call, allow); err != nil {
			return nil, call, errStatus(http.StatusForbidden, err)
		}
	} else if err := WriteAllowed(call); err != nil {
		return nil, call, errStatus(http.StatusForbidden, err)
	}
	if ok, reason := NamespaceAllowed(row.K8sNamespaces, call); !ok {
		if reason == "cluster_scope_denied" {
			return nil, call, errStatus(http.StatusForbidden, fmt.Errorf("cluster-scoped request denied by namespace ACL"))
		}
		return nil, call, errStatus(http.StatusForbidden, fmt.Errorf("namespace not allowed by policy"))
	}
	if msg, deny := g.denyHTTPACL(ctx, row, method, path, ""); deny {
		return nil, call, errStatus(http.StatusForbidden, fmt.Errorf("%s", msg))
	}
	if ev, deny := g.denyOpRisk(ctx, row, call, ""); deny {
		if ev.NeedsStepUp() {
			if g.onNeedMFA != nil {
				_ = g.onNeedMFA(ctx, row, ev)
			}
			return nil, call, errStatus(http.StatusForbidden, &policy.StepUpError{Result: ev})
		}
		return nil, call, errStatus(http.StatusForbidden, fmt.Errorf("%s", ev.DenyMessage()))
	}
	if allow == "" && NeedsNamespaceListFilter(row.K8sNamespaces, call) {
		body := SyntheticNamespaceList(row.K8sNamespaces, false)
		g.noteCall(ctx, row, call, method, path, http.StatusOK)
		return nil, call, errSynthetic{body: body}
	}
	up, err := g.ensureUpstream(ctx, row)
	if err != nil {
		return nil, call, err
	}
	if row.Status == "pending" {
		_ = g.sessions.MarkActive(ctx, row.ID)
		_ = g.audit.Record(ctx, &row.UserID, "session.started", "session", row.ID.String(), "", "k8s", map[string]any{
			"protocol": "kubectl", "via": "browser",
		})
	}
	_ = g.sessions.Touch(ctx, row.ID)
	return up, call, nil
}

func allowPodSubresource(call APICall, sub string) error {
	sub = strings.ToLower(strings.TrimSpace(sub))
	switch sub {
	case "exec", "attach", "portforward":
	default:
		return fmt.Errorf("unsupported subresource")
	}
	if !strings.EqualFold(call.Resource, "pods") || !strings.EqualFold(call.Subresource, sub) {
		return fmt.Errorf("%s allowed only on pods/%s", sub, sub)
	}
	return nil
}

func WriteAllowed(call APICall) error {
	if call.Denied() {
		return fmt.Errorf("exec/attach/port-forward denied")
	}
	if call.Verb == "deletecollection" {
		return fmt.Errorf("delete collection denied")
	}
	return nil
}

type errSynthetic struct{ body []byte }

func (e errSynthetic) Error() string { return "synthetic" }

type statusErr struct {
	code int
	err  error
}

func (e statusErr) Error() string { return e.err.Error() }
func (e statusErr) Unwrap() error { return e.err }

func errStatus(code int, err error) error {
	return statusErr{code: code, err: err}
}

func HTTPStatus(err error) int {
	return statusFromErr(err)
}

func statusFromErr(err error) int {
	if err == nil {
		return 0
	}
	if se, ok := err.(statusErr); ok {
		return se.code
	}
	return 0
}

func (g *Gateway) noteCall(ctx context.Context, row sessionsvc.Session, call APICall, method, path string, status int) {
	if g == nil {
		return
	}
	g.mu.Lock()
	u := g.upstreams[row.ID]
	g.mu.Unlock()
	if u != nil && u.rec != nil {
		u.rec.WriteCall(call, method, path, status)
	}
	payload := map[string]any{
		"verb": call.Verb, "resource": call.Resource, "api_group": call.APIGroup,
		"namespace": call.Namespace, "name": call.Name, "status": status, "via": "browser",
		"method": method, "subresource": call.Subresource,
	}
	_ = g.sessions.AddEvent(ctx, row.ID, "k8s", payload)
	_ = g.audit.Record(ctx, &row.UserID, "session.k8s", "session", row.ID.String(), "", "k8s", payload)
	if g.live != nil {
		g.live.FanoutSQL(ctx, row.ID, map[string]any{
			"type": "k8s", "verb": call.Verb, "resource": call.Resource,
			"namespace": call.Namespace, "name": call.Name, "status": status, "via": "browser",
		})
	}
}

func applyUpstreamAuth(h http.Header, up *sessionUpstream) {
	if up == nil || h == nil {
		return
	}
	if up.up != nil && up.up.Token != "" {
		h.Set("Authorization", "Bearer "+up.up.Token)
	}
	if up.impersonateUser != "" {
		ApplyImpersonate(h, up.impersonateUser, up.impersonateGroups, up.impersonateUID)
	}
}

func httpClient(up *Upstream, timeout time.Duration) *http.Client {
	c := &http.Client{Timeout: timeout}
	if up != nil && up.Transport != nil {
		c.Transport = up.Transport
	}
	return c
}
