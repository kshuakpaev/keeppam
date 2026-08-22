package citrix

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CtxStaSuccessBody is a text/plain body many STA clients accept on ticket OK.
// Line1 = ticket, line2 = optional farm hint (KeepPAM session id).
func CtxStaSuccessBody(ticket, farmHint string) string {
	ticket = strings.TrimSpace(strings.ToUpper(ticket))
	if farmHint == "" {
		return ticket + "\n"
	}
	return ticket + "\n" + farmHint + "\n"
}

// ProbeExternalSTA GETs ticket against a Citrix STA URL (CtxSta.dll or compatible).
// staBase may be full URL to CtxSta.dll or a host root (Scripts/CtxSta.dll appended).
func ProbeExternalSTA(ctx context.Context, client *http.Client, staBase, ticket string) (ok bool, body string, err error) {
	ticket = strings.TrimSpace(ticket)
	if ticket == "" || strings.TrimSpace(staBase) == "" {
		return false, "", fmt.Errorf("sta url and ticket required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	u, err := buildSTAQueryURL(staBase, ticket)
	if err != nil {
		return false, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	body = string(b)
	if res.StatusCode >= 200 && res.StatusCode < 300 && len(strings.TrimSpace(body)) > 0 {
		return true, body, nil
	}
	if res.StatusCode == http.StatusNotFound || res.StatusCode >= 400 {
		return false, body, nil
	}
	return false, body, nil
}

func buildSTAQueryURL(staBase, ticket string) (string, error) {
	staBase = strings.TrimSpace(staBase)
	if !strings.Contains(staBase, "://") {
		staBase = "http://" + staBase
	}
	u, err := url.Parse(staBase)
	if err != nil {
		return "", err
	}
	path := strings.ToLower(u.Path)
	if path == "" || path == "/" {
		u.Path = "/Scripts/CtxSta.dll"
	} else if !strings.Contains(path, "ctxsta") && !strings.HasSuffix(path, ".dll") {
		u.Path = strings.TrimRight(u.Path, "/") + "/Scripts/CtxSta.dll"
	}
	q := u.Query()
	q.Set("ticket", strings.ToUpper(strings.TrimSpace(ticket)))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ProbeSTAURLs tries comma-separated STA bases until one accepts the ticket.
func ProbeSTAURLs(ctx context.Context, client *http.Client, csv, ticket string) (ok bool, which, body string, err error) {
	for _, raw := range strings.Split(csv, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ok, body, err = ProbeExternalSTA(ctx, client, raw, ticket)
		if err != nil {
			continue
		}
		if ok {
			return true, raw, body, nil
		}
	}
	if csv == "" {
		return false, "", "", fmt.Errorf("no sta urls")
	}
	return false, "", body, nil
}
