package k8sproxy

import (
	"net/http"
	"strings"
)

type APICall struct {
	Verb      string `json:"verb"`
	APIGroup  string `json:"api_group,omitempty"`
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Watch     bool   `json:"watch,omitempty"`
}

var deniedSubresources = map[string]bool{
	"exec":        true,
	"attach":      true,
	"portforward": true,
	"proxy":       true,
}

func ParseAPIPath(method, path string, qWatch bool) APICall {
	c := APICall{}
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		c.Resource = "root"
		c.Verb = verbFrom(method, false, qWatch)
		c.Watch = qWatch
		return c
	}
	switch parts[0] {
	case "api":
		// /api or /api/v1/...
		if len(parts) == 1 {
			c.Resource = "api"
			c.Verb = "get"
			return c
		}
		c.fillCore(parts[2:])
	case "apis":
		// /apis or /apis/{group}/{version}/...
		if len(parts) == 1 {
			c.Resource = "apis"
			c.Verb = "get"
			return c
		}
		if len(parts) >= 2 {
			c.APIGroup = parts[1]
		}
		rest := []string{}
		if len(parts) >= 3 {
			rest = parts[3:]
		}
		c.fillCore(rest)
	default:
		c.Resource = parts[0]
	}
	hasName := c.Name != ""
	c.Verb = verbFrom(method, hasName, qWatch)
	c.Watch = qWatch || c.Verb == "watch"
	return c
}

func (c *APICall) fillCore(parts []string) {
	if len(parts) == 0 {
		c.Resource = "api"
		return
	}
	if parts[0] == "namespaces" && len(parts) >= 2 {
		c.Namespace = parts[1]
		parts = parts[2:]
	}
	if len(parts) == 0 {
		c.Resource = "namespaces"
		if c.Namespace != "" {
			c.Name = c.Namespace
			c.Namespace = ""
			c.Resource = "namespaces"
		}
		return
	}
	c.Resource = parts[0]
	if len(parts) >= 2 {
		c.Name = parts[1]
	}
	if len(parts) >= 3 {
		c.Subresource = parts[2]
	}
}

func verbFrom(method string, hasName, watch bool) string {
	m := strings.ToUpper(method)
	if watch && (m == http.MethodGet || m == "") {
		return "watch"
	}
	switch m {
	case http.MethodPost:
		return "create"
	case http.MethodPut:
		return "update"
	case http.MethodPatch:
		return "patch"
	case http.MethodDelete:
		if hasName {
			return "delete"
		}
		return "deletecollection"
	default:
		if hasName {
			return "get"
		}
		return "list"
	}
}

func (c APICall) Denied() bool {
	if deniedSubresources[strings.ToLower(c.Subresource)] {
		return true
	}
	return false
}

func IsUpgrade(r *http.Request) bool {
	conn := strings.ToLower(r.Header.Get("Connection"))
	return strings.Contains(conn, "upgrade") || r.Header.Get("Upgrade") != ""
}
