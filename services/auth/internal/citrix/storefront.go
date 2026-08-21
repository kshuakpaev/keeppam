package citrix

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PublishedResource is a StoreFront (or compatible) published app/desktop.
type PublishedResource struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path,omitempty"`
	LaunchURL   string `json:"launch_url,omitempty"`
	IconURL     string `json:"icon_url,omitempty"`
	InitialProg string `json:"initial_program,omitempty"`
}

// StoreFrontClient is a read-only broker against Citrix StoreFront HTTP APIs (phase 2).
type StoreFrontClient struct {
	BaseURL  string
	User     string
	Password string
	HTTP     *http.Client
}

func (c *StoreFrontClient) httpClient() *http.Client {
	if c != nil && c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (c *StoreFrontClient) base() (*url.URL, error) {
	if c == nil || strings.TrimSpace(c.BaseURL) == "" {
		return nil, fmt.Errorf("storefront url required")
	}
	raw := strings.TrimSpace(c.BaseURL)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	return url.Parse(raw)
}

// Discovery hits StoreFront discovery document (best-effort).
func (c *StoreFrontClient) Discovery(ctx context.Context) (map[string]any, error) {
	base, err := c.base()
	if err != nil {
		return nil, err
	}
	candidates := []string{
		strings.TrimRight(base.String(), "/") + "/discovery",
		strings.TrimRight(base.String(), "/") + "/Citrix/Store/discovery",
	}
	var last error
	for _, u := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			last = err
			continue
		}
		c.applyAuth(req)
		res, err := c.httpClient().Do(req)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			var out map[string]any
			if json.Unmarshal(b, &out) == nil {
				return out, nil
			}
			return map[string]any{"raw": string(b), "url": u}, nil
		}
		last = fmt.Errorf("discovery %s: HTTP %d", u, res.StatusCode)
	}
	if last == nil {
		last = fmt.Errorf("discovery failed")
	}
	return nil, last
}

// ListResources enumerates published apps (read-only). Tries several StoreFront paths.
func (c *StoreFrontClient) ListResources(ctx context.Context) ([]PublishedResource, error) {
	base, err := c.base()
	if err != nil {
		return nil, err
	}
	root := strings.TrimRight(base.String(), "/")
	candidates := []string{
		root + "/resources/v2",
		root + "/Citrix/Store/resources/v2",
		root + "/Citrix/StoreWeb/resources/list",
		root + "/Citrix/Store/resources/list",
	}
	var last error
	for _, u := range candidates {
		list, err := c.getResources(ctx, u)
		if err != nil {
			last = err
			continue
		}
		if len(list) > 0 {
			return list, nil
		}
		last = fmt.Errorf("empty resources at %s", u)
	}
	if last == nil {
		last = fmt.Errorf("no resources")
	}
	return nil, last
}

func (c *StoreFrontClient) getResources(ctx context.Context, rawURL string) ([]PublishedResource, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, application/vnd.citrix.resources+xml, */*")
	c.applyAuth(req)
	res, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, truncate(string(b), 200))
	}
	return parseResourcesJSON(b)
}

func (c *StoreFrontClient) applyAuth(req *http.Request) {
	if c == nil {
		return
	}
	if c.User != "" {
		req.SetBasicAuth(c.User, c.Password)
	}
}

func parseResourcesJSON(b []byte) ([]PublishedResource, error) {
	// Shape A: { "resources": [ {...} ] }
	var wrap struct {
		Resources []sfRes `json:"resources"`
	}
	if err := json.Unmarshal(b, &wrap); err == nil && len(wrap.Resources) > 0 {
		return mapSF(wrap.Resources), nil
	}
	// Shape B: bare array
	var arr []sfRes
	if err := json.Unmarshal(b, &arr); err == nil && len(arr) > 0 {
		return mapSF(arr), nil
	}
	// Shape C: { "resource": ... } single
	var one struct {
		Resource sfRes `json:"resource"`
	}
	if err := json.Unmarshal(b, &one); err == nil && (one.Resource.Name != "" || one.Resource.ID != "") {
		return mapSF([]sfRes{one.Resource}), nil
	}
	return nil, fmt.Errorf("unrecognized resources payload")
}

type sfRes struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Title          string `json:"title"`
	Path           string `json:"path"`
	Launchstatus   string `json:"launchstatusurl"`
	LaunchURL      string `json:"launchurl"`
	IconURL        string `json:"iconurl"`
	InitialProgram string `json:"initialprogram"`
}

func mapSF(in []sfRes) []PublishedResource {
	out := make([]PublishedResource, 0, len(in))
	for _, r := range in {
		name := r.Name
		if name == "" {
			name = r.Title
		}
		launch := r.LaunchURL
		if launch == "" {
			launch = r.Launchstatus
		}
		id := r.ID
		if id == "" {
			id = name
		}
		prog := r.InitialProgram
		if prog == "" && name != "" {
			prog = "#" + name
		}
		out = append(out, PublishedResource{
			ID: id, Name: name, Path: r.Path,
			LaunchURL: launch, IconURL: r.IconURL, InitialProg: prog,
		})
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
