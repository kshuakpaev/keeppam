package appaccess

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
)

type ProxyRecorder struct {
	mu    sync.Mutex
	f     *os.File
	start time.Time
}

func NewProxyRecorder(path string) (*ProxyRecorder, error) {
	if err := os.MkdirAll(dirOf(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	r := &ProxyRecorder{f: f, start: time.Now().UTC()}
	_ = r.write(map[string]any{"type": "header", "format": "keeppam-http", "version": 1, "started_at": r.start.Format(time.RFC3339Nano)})
	return r, nil
}

func (r *ProxyRecorder) Record(method, path string, status int) {
	if r == nil {
		return
	}
	_ = r.write(map[string]any{
		"type": "http", "ts": time.Now().UTC().Format(time.RFC3339Nano),
		"sec": time.Since(r.start).Seconds(),
		"method": method, "path": path, "status": status, "body_redacted": true,
	})
}

func (r *ProxyRecorder) Close() error {
	if r == nil || r.f == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

func (r *ProxyRecorder) write(v any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = r.f.Write(append(b, '\n'))
	return err
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

func ReverseProxy(creds assets.TargetCreds, integ Integration, rec *ProxyRecorder, sessionID uuid.UUID, pathPrefix string) (*httputil.ReverseProxy, error) {
	target := integ.LoginURL
	if target == "" {
		scheme := "https"
		if creds.Asset.Port == 80 {
			scheme = "http"
		}
		host := creds.Asset.Address
		if creds.Asset.Port > 0 && creds.Asset.Port != 443 && creds.Asset.Port != 80 {
			host = fmt.Sprintf("%s:%d", host, creds.Asset.Port)
		}
		target = scheme + "://" + host
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	orig := proxy.Director
	proxy.Director = func(req *http.Request) {
		orig(req)
		req.Host = u.Host
		if integ.AuthMode == "header_inject" && integ.HeaderName != "" {
			req.Header.Set(integ.HeaderName, creds.Secret)
		} else if integ.AuthMode == "vault_password" {
			req.SetBasicAuth(creds.Account.Username, creds.Secret)
		}
		req.Header.Set("X-KeepPAM-Session", sessionID.String())
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if rec != nil && resp.Request != nil {
			rec.Record(resp.Request.Method, resp.Request.URL.RequestURI(), resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			if next := rewritePrefixedLocation(loc, pathPrefix, u); next != loc {
				resp.Header.Set("Location", next)
			}
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
	}
	return proxy, nil
}

// rewritePrefixedLocation keeps in-app redirects under the PAM prefix.
// Absolute Location to another host (IdP/SSO) is left unchanged.
func rewritePrefixedLocation(loc, prefix string, upstream *url.URL) string {
	prefix = strings.TrimSuffix(prefix, "/")
	if loc == "" || prefix == "" {
		return loc
	}
	u, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	if u.IsAbs() {
		if upstream == nil || !sameHTTPHost(u, upstream) {
			return loc
		}
		out := prefix + u.EscapedPath()
		if u.RawQuery != "" {
			out += "?" + u.RawQuery
		}
		if u.Fragment != "" {
			out += "#" + u.Fragment
		}
		return out
	}
	if strings.HasPrefix(u.Path, "/") {
		u.Path = prefix + u.Path
		u.RawPath = ""
		return u.String()
	}
	return loc
}

func sameHTTPHost(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(canonicalHost(a), canonicalHost(b))
}

func canonicalHost(u *url.URL) string {
	host := strings.ToLower(u.Host)
	if !strings.Contains(host, ":") {
		switch u.Scheme {
		case "http":
			host += ":80"
		case "https":
			host += ":443"
		}
	}
	return host
}
