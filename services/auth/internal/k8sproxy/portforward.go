package k8sproxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/keeppam/auth/internal/sessionsvc"
)

const (
	pfDataCh  = 0
	pfErrorCh = 1
	maxPFBody = 1 << 20
	maxPFReq  = 64 << 10
)

type PortForwardHTTPResult struct {
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Truncated bool              `json:"truncated,omitempty"`
}

func (g *Gateway) PortForwardHTTP(ctx context.Context, row sessionsvc.Session, ns, pod string, port int, method, path string, body []byte) (PortForwardHTTPResult, error) {
	var res PortForwardHTTPResult
	ns = strings.TrimSpace(ns)
	pod = strings.TrimSpace(pod)
	if ns == "" || pod == "" {
		return res, fmt.Errorf("namespace and pod required")
	}
	if port < 1 || port > 65535 {
		return res, fmt.Errorf("port must be 1..65535")
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		return res, fmt.Errorf("method %s not allowed", method)
	}
	path = sanitizePFPath(path)
	if len(body) > maxPFReq {
		return res, fmt.Errorf("request body too large")
	}

	up, err := g.prepStream(ctx, row, ns, pod, "portforward")
	if err != nil {
		return res, err
	}
	conn, err := dialPortForward(ctx, up, ns, pod, port)
	if err != nil {
		g.notePortForward(ctx, row, ns, pod, port, method, path, http.StatusBadGateway)
		return res, err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := skipPortForwardHello(ctx, conn); err != nil {
		g.notePortForward(ctx, row, ns, pod, port, method, path, http.StatusBadGateway)
		return res, err
	}
	req := buildPFHTTPRequest(method, path, port, body)
	if err := WriteExecStdin(conn, req); err != nil { // channel 0 = data, same as stdin
		g.notePortForward(ctx, row, ns, pod, port, method, path, http.StatusBadGateway)
		return res, err
	}
	raw, err := readPFHTTP(ctx, conn)
	if err != nil {
		g.notePortForward(ctx, row, ns, pod, port, method, path, http.StatusBadGateway)
		return res, err
	}
	res, err = parseHTTPResponse(raw)
	status := res.Status
	if status == 0 {
		status = http.StatusOK
	}
	if err != nil {
		status = http.StatusBadGateway
	}
	g.notePortForward(ctx, row, ns, pod, port, method, path, status)
	return res, err
}

func (g *Gateway) notePortForward(ctx context.Context, row sessionsvc.Session, ns, pod string, port int, method, path string, status int) {
	call := APICall{Verb: "create", Resource: "pods", Namespace: ns, Name: pod, Subresource: "portforward"}
	g.noteCall(ctx, row, call, http.MethodPost, "/portforward", status)
	_ = g.audit.Record(ctx, &row.UserID, "session.k8s.portforward", "session", row.ID.String(), "", "k8s", map[string]any{
		"namespace": ns, "pod": pod, "port": port, "method": method, "path": path, "status": status, "via": "browser",
		"body_redacted": true,
	})
}

func dialPortForward(ctx context.Context, up *sessionUpstream, ns, pod string, port int) (*websocket.Conn, error) {
	if up == nil || up.up == nil || up.up.Server == nil {
		return nil, fmt.Errorf("k8s upstream required")
	}
	u := *up.up.Server
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	u.Path = "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods/" + url.PathEscape(pod) + "/portforward"
	q := url.Values{}
	q.Set("ports", strconv.Itoa(port))
	u.RawQuery = q.Encode()

	hdr := http.Header{}
	applyUpstreamAuth(hdr, up)
	d := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		Subprotocols:     []string{"v5.channel.k8s.io", "v4.channel.k8s.io", "v3.channel.k8s.io", "portforward.k8s.io"},
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
		return nil, fmt.Errorf("portforward: %s", msg)
	}
	return conn, nil
}

func skipPortForwardHello(ctx context.Context, conn *websocket.Conn) error {
	// First frames are often 2-byte port acks on data/error channels.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				return nil
			}
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
				return fmt.Errorf("portforward closed during handshake")
			}
			return nil
		}
		if len(msg) == 0 {
			continue
		}
		ch, payload := msg[0], msg[1:]
		if ch == pfErrorCh && len(payload) > 2 {
			s := strings.TrimSpace(string(payload))
			if s != "" {
				return fmt.Errorf("portforward: %s", s)
			}
		}
		if len(payload) == 2 {
			continue
		}
		if ch == pfDataCh && looksLikeHTTP(payload) {
			// Some servers skip the ack; stash is not possible — caller already needs a request first.
			return nil
		}
	}
	return nil
}

func looksLikeHTTP(p []byte) bool {
	s := strings.TrimSpace(string(p))
	return strings.HasPrefix(s, "HTTP/") || strings.HasPrefix(s, "http/")
}

func buildPFHTTPRequest(method, path string, port int, body []byte) []byte {
	var b strings.Builder
	b.WriteString(method)
	b.WriteByte(' ')
	b.WriteString(path)
	b.WriteString(" HTTP/1.1\r\n")
	b.WriteString("Host: 127.0.0.1:")
	b.WriteString(strconv.Itoa(port))
	b.WriteString("\r\n")
	b.WriteString("Connection: close\r\n")
	b.WriteString("Accept: */*\r\n")
	if len(body) > 0 {
		b.WriteString("Content-Length: ")
		b.WriteString(strconv.Itoa(len(body)))
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	out := []byte(b.String())
	if len(body) > 0 {
		out = append(out, body...)
	}
	return out
}

func sanitizePFPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		p = "/"
	}
	if i := strings.IndexByte(p, '?'); i == 0 {
		p = "/" + p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if i := strings.IndexAny(p, "\r\n"); i >= 0 {
		p = p[:i]
	}
	if len(p) > 2048 {
		p = p[:2048]
	}
	return p
}

func readPFHTTP(ctx context.Context, conn *websocket.Conn) ([]byte, error) {
	var buf bytes.Buffer
	for {
		if err := ctx.Err(); err != nil {
			if buf.Len() > 0 {
				return buf.Bytes(), nil
			}
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if buf.Len() > 0 {
				return buf.Bytes(), nil
			}
			return nil, err
		}
		if len(msg) == 0 {
			continue
		}
		ch, payload := msg[0], msg[1:]
		switch ch {
		case pfErrorCh:
			if len(payload) > 2 {
				s := strings.TrimSpace(string(payload))
				if s != "" && buf.Len() == 0 {
					return nil, fmt.Errorf("portforward: %s", s)
				}
			}
		case pfDataCh:
			if len(payload) == 2 && buf.Len() == 0 {
				continue
			}
			buf.Write(payload)
			if buf.Len() > maxPFBody+4096 {
				return buf.Bytes(), nil
			}
			if httpResponseComplete(buf.Bytes()) {
				return buf.Bytes(), nil
			}
		}
	}
}

func httpResponseComplete(raw []byte) bool {
	head, body, ok := splitHTTP(raw)
	if !ok {
		return false
	}
	cl := headerContentLength(head)
	if cl >= 0 {
		return len(body) >= cl
	}
	return bytes.Contains(bytes.ToLower(head), []byte("connection: close")) && bytes.HasSuffix(body, []byte("\r\n"))
}

func splitHTTP(raw []byte) (head, body []byte, ok bool) {
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i < 0 {
		return nil, nil, false
	}
	return raw[:i], raw[i+4:], true
}

func headerContentLength(head []byte) int {
	sc := bufio.NewScanner(bytes.NewReader(head))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, ':'); i > 0 {
			if strings.EqualFold(strings.TrimSpace(line[:i]), "Content-Length") {
				n, err := strconv.Atoi(strings.TrimSpace(line[i+1:]))
				if err == nil {
					return n
				}
			}
		}
	}
	return -1
}

func parseHTTPResponse(raw []byte) (PortForwardHTTPResult, error) {
	var res PortForwardHTTPResult
	res.Headers = map[string]string{}
	if len(raw) == 0 {
		return res, fmt.Errorf("empty response")
	}
	head, body, ok := splitHTTP(raw)
	if !ok {
		res.Body = string(raw)
		if len(res.Body) > maxPFBody {
			res.Body = res.Body[:maxPFBody]
			res.Truncated = true
		}
		return res, fmt.Errorf("invalid http response")
	}
	r := bufio.NewReader(bytes.NewReader(append(append([]byte{}, head...), "\r\n\r\n"...)))
	tp := textproto.NewReader(r)
	line, err := tp.ReadLine()
	if err != nil {
		return res, err
	}
	res.Status = parseStatusLine(line)
	mime, err := tp.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return res, err
	}
	for k, vs := range mime {
		if len(vs) == 0 {
			continue
		}
		lk := strings.ToLower(k)
		if lk == "set-cookie" || strings.Contains(lk, "authorization") {
			res.Headers[k] = "(redacted)"
			continue
		}
		res.Headers[k] = vs[0]
	}
	if len(body) > maxPFBody {
		body = body[:maxPFBody]
		res.Truncated = true
	}
	res.Body = string(body)
	return res, nil
}

func parseStatusLine(line string) int {
	// HTTP/1.1 200 OK
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(parts[1])
	return n
}
