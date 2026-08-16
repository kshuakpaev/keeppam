package k8sproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/keeppam/auth/internal/sessionsvc"
)

const (
	chanStdin  = 0
	chanStdout = 1
	chanStderr = 2
	chanError  = 3
	chanResize = 4
)

type ExecResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Message  string `json:"message,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
}

func (g *Gateway) ExecOnce(ctx context.Context, row sessionsvc.Session, ns, pod, container string, command []string) (ExecResult, error) {
	up, err := g.prepExec(ctx, row, ns, pod)
	if err != nil {
		return ExecResult{}, err
	}
	conn, err := dialExec(ctx, up, ns, pod, container, command, false, false)
	if err != nil {
		g.noteExec(ctx, row, ns, pod, container, command, http.StatusBadGateway)
		return ExecResult{}, err
	}
	defer conn.Close()
	res, err := readExecResult(ctx, conn)
	status := http.StatusOK
	if err != nil {
		status = http.StatusBadGateway
	}
	g.noteExec(ctx, row, ns, pod, container, command, status)
	return res, err
}

func (g *Gateway) DialExec(ctx context.Context, row sessionsvc.Session, ns, pod, container string, command []string, tty bool) (*websocket.Conn, error) {
	up, err := g.prepStream(ctx, row, ns, pod, "exec")
	if err != nil {
		return nil, err
	}
	conn, err := dialPodStream(ctx, up, ns, pod, container, "exec", command, true, tty)
	if err != nil {
		g.noteStream(ctx, row, ns, pod, container, "exec", command, http.StatusBadGateway)
		return nil, err
	}
	g.noteStream(ctx, row, ns, pod, container, "exec", command, http.StatusSwitchingProtocols)
	return conn, nil
}

func (g *Gateway) DialAttach(ctx context.Context, row sessionsvc.Session, ns, pod, container string, tty bool) (*websocket.Conn, error) {
	up, err := g.prepStream(ctx, row, ns, pod, "attach")
	if err != nil {
		return nil, err
	}
	conn, err := dialPodStream(ctx, up, ns, pod, container, "attach", nil, true, tty)
	if err != nil {
		g.noteStream(ctx, row, ns, pod, container, "attach", nil, http.StatusBadGateway)
		return nil, err
	}
	g.noteStream(ctx, row, ns, pod, container, "attach", nil, http.StatusSwitchingProtocols)
	return conn, nil
}

func (g *Gateway) prepExec(ctx context.Context, row sessionsvc.Session, ns, pod string) (*sessionUpstream, error) {
	return g.prepStream(ctx, row, ns, pod, "exec")
}

func (g *Gateway) prepStream(ctx context.Context, row sessionsvc.Session, ns, pod, sub string) (*sessionUpstream, error) {
	ns = strings.TrimSpace(ns)
	pod = strings.TrimSpace(pod)
	sub = strings.ToLower(strings.TrimSpace(sub))
	if ns == "" || pod == "" {
		return nil, fmt.Errorf("namespace and pod required")
	}
	if sub == "" {
		sub = "exec"
	}
	path := "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods/" + url.PathEscape(pod) + "/" + sub
	up, _, err := g.prepareBrowser(ctx, row, CallOptions{Method: http.MethodGet, Path: path, AllowSub: sub})
	if err != nil {
		return nil, err
	}
	return up, nil
}

func (g *Gateway) noteExec(ctx context.Context, row sessionsvc.Session, ns, pod, container string, command []string, status int) {
	g.noteStream(ctx, row, ns, pod, container, "exec", command, status)
}

func (g *Gateway) noteStream(ctx context.Context, row sessionsvc.Session, ns, pod, container, sub string, command []string, status int) {
	sub = strings.ToLower(strings.TrimSpace(sub))
	if sub == "" {
		sub = "exec"
	}
	call := APICall{Verb: "create", Resource: "pods", Namespace: ns, Name: pod, Subresource: sub}
	g.noteCall(ctx, row, call, http.MethodPost, "/"+sub, status)
	action := "session.k8s." + sub
	payload := map[string]any{
		"namespace": ns, "pod": pod, "container": container, "status": status, "via": "browser", "subresource": sub,
	}
	if len(command) > 0 {
		payload["command"] = command
	}
	_ = g.audit.Record(ctx, &row.UserID, action, "session", row.ID.String(), "", "k8s", payload)
}

func dialExec(ctx context.Context, up *sessionUpstream, ns, pod, container string, command []string, stdin, tty bool) (*websocket.Conn, error) {
	return dialPodStream(ctx, up, ns, pod, container, "exec", command, stdin, tty)
}

func dialPodStream(ctx context.Context, up *sessionUpstream, ns, pod, container, sub string, command []string, stdin, tty bool) (*websocket.Conn, error) {
	if up == nil || up.up == nil || up.up.Server == nil {
		return nil, fmt.Errorf("k8s upstream required")
	}
	sub = strings.ToLower(strings.TrimSpace(sub))
	if sub == "" {
		sub = "exec"
	}
	if sub == "exec" {
		command = sanitizeCommand(command)
		if len(command) == 0 {
			return nil, fmt.Errorf("command required")
		}
	}
	u := *up.up.Server
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	u.Path = "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods/" + url.PathEscape(pod) + "/" + sub
	q := url.Values{}
	if sub == "exec" {
		for _, c := range command {
			q.Add("command", c)
		}
	}
	q.Set("stdout", "true")
	q.Set("stderr", "true")
	if stdin {
		q.Set("stdin", "true")
	} else {
		q.Set("stdin", "false")
	}
	if tty {
		q.Set("tty", "true")
	} else {
		q.Set("tty", "false")
	}
	if c := strings.TrimSpace(container); c != "" {
		q.Set("container", c)
	}
	u.RawQuery = q.Encode()

	hdr := http.Header{}
	applyUpstreamAuth(hdr, up)
	d := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		Subprotocols:     []string{"v5.channel.k8s.io", "v4.channel.k8s.io", "v3.channel.k8s.io"},
	}
	if up.up.Transport != nil && up.up.Transport.TLSClientConfig != nil {
		d.TLSClientConfig = up.up.Transport.TLSClientConfig
	}
	conn, resp, err := d.DialContext(ctx, u.String(), hdr)
	if err != nil {
		msg := err.Error()
		if resp != nil && resp.Body != nil {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
			if s := k8sStatusMessage(raw); s != "" && s != "error" {
				msg = s
			}
		}
		return nil, fmt.Errorf("%s: %s", sub, msg)
	}
	return conn, nil
}

func ProxyExec(browser, upstream *websocket.Conn, cols, rows int) {
	if browser == nil || upstream == nil {
		return
	}
	_ = WriteExecResize(upstream, cols, rows)
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, msg, err := browser.ReadMessage()
			if err != nil {
				return
			}
			var m struct {
				Type string `json:"type"`
				Data string `json:"data"`
				Cols int    `json:"cols"`
				Rows int    `json:"rows"`
			}
			if json.Unmarshal(msg, &m) != nil {
				continue
			}
			switch m.Type {
			case "input":
				_ = WriteExecStdin(upstream, []byte(m.Data))
			case "resize":
				_ = WriteExecResize(upstream, m.Cols, m.Rows)
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, msg, err := upstream.ReadMessage()
			if err != nil {
				return
			}
			if len(msg) == 0 {
				continue
			}
			switch msg[0] {
			case chanStdout, chanStderr:
				_ = browser.WriteMessage(websocket.BinaryMessage, msg[1:])
			case chanError:
				st := parseExecStatus(msg[1:])
				if st.Failure && st.Message != "" {
					b, _ := json.Marshal(map[string]string{"type": "error", "message": st.Message})
					_ = browser.WriteMessage(websocket.TextMessage, b)
				}
				return
			}
		}
	}()
	<-done
	_ = upstream.Close()
	_ = browser.Close()
}

func readExecResult(ctx context.Context, conn *websocket.Conn) (ExecResult, error) {
	var res ExecResult
	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(25 * time.Second))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
				return res, nil
			}
			if res.Stdout != "" || res.Stderr != "" {
				return res, nil
			}
			return res, err
		}
		if len(msg) == 0 {
			continue
		}
		switch msg[0] {
		case chanStdout:
			res.Stdout += string(msg[1:])
			if len(res.Stdout) > 1<<20 {
				res.Stdout = res.Stdout[:1<<20]
			}
		case chanStderr:
			res.Stderr += string(msg[1:])
			if len(res.Stderr) > 1<<20 {
				res.Stderr = res.Stderr[:1<<20]
			}
		case chanError:
			st := parseExecStatus(msg[1:])
			res.Message = st.Message
			res.ExitCode = st.Exit
			if st.Failure && res.Stdout == "" && res.Stderr == "" {
				return res, fmt.Errorf("%s", strings.TrimSpace(st.Message))
			}
			return res, nil
		}
	}
}

type execStatus struct {
	Message string
	Exit    int
	Failure bool
}

func parseExecStatus(raw []byte) execStatus {
	var st struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Reason  string `json:"reason"`
		Details struct {
			Causes []struct {
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"causes"`
		} `json:"details"`
	}
	out := execStatus{}
	if json.Unmarshal(raw, &st) != nil {
		out.Message = strings.TrimSpace(string(raw))
		return out
	}
	out.Message = strings.TrimSpace(st.Message)
	if out.Message == "" {
		out.Message = strings.TrimSpace(st.Reason)
	}
	out.Failure = strings.EqualFold(st.Status, "Failure")
	for _, c := range st.Details.Causes {
		if strings.EqualFold(c.Reason, "ExitCode") {
			fmt.Sscanf(c.Message, "%d", &out.Exit)
		}
	}
	return out
}

func WriteExecStdin(conn *websocket.Conn, data []byte) error {
	if conn == nil || len(data) == 0 {
		return nil
	}
	msg := make([]byte, 1+len(data))
	msg[0] = chanStdin
	copy(msg[1:], data)
	return conn.WriteMessage(websocket.BinaryMessage, msg)
}

func WriteExecResize(conn *websocket.Conn, cols, rows int) error {
	if conn == nil || cols <= 0 || rows <= 0 {
		return nil
	}
	body, _ := json.Marshal(map[string]int{"Width": cols, "Height": rows})
	msg := append([]byte{chanResize}, body...)
	return conn.WriteMessage(websocket.BinaryMessage, msg)
}

func sanitizeCommand(in []string) []string {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || strings.ContainsRune(s, 0) {
			continue
		}
		if len(s) > 256 {
			s = s[:256]
		}
		out = append(out, s)
		if len(out) >= 32 {
			break
		}
	}
	return out
}
