package k8sproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/keeppam/auth/internal/sessionsvc"
)

type ApplyResult struct {
	Verb      string          `json:"verb"`
	Resource  string          `json:"resource"`
	Group     string          `json:"group,omitempty"`
	Namespace string          `json:"namespace,omitempty"`
	Name      string          `json:"name"`
	Status    int             `json:"status"`
	Object    json.RawMessage `json:"object,omitempty"`
	Error     string          `json:"error,omitempty"`
}

func (g *Gateway) ApplyManifests(ctx context.Context, row sessionsvc.Session, raw []byte, defaultNS string) ([]ApplyResult, error) {
	docs, err := ParseManifests(raw)
	if err != nil {
		return nil, err
	}
	out := make([]ApplyResult, 0, len(docs))
	for _, doc := range docs {
		out = append(out, g.applyOne(ctx, row, doc, defaultNS))
	}
	return out, nil
}

func (g *Gateway) applyOne(ctx context.Context, row sessionsvc.Session, obj map[string]any, defaultNS string) ApplyResult {
	apiVersion, kindName, ns, name := ManifestIdentity(obj)
	res := ApplyResult{Name: name, Namespace: ns, Verb: "create"}
	if name == "" || kindName == "" {
		res.Status = http.StatusBadRequest
		res.Error = "kind and metadata.name required"
		return res
	}
	kind, err := LookupKindFromGVK(apiVersion, kindName)
	if err != nil {
		res.Status = http.StatusBadRequest
		res.Error = err.Error()
		return res
	}
	res.Resource, res.Group = kind.Resource, kind.Group
	if kind.Namespaced {
		if ns == "" {
			ns = strings.TrimSpace(defaultNS)
		}
		if ns == "" {
			res.Status = http.StatusBadRequest
			res.Error = "namespace required"
			return res
		}
		if md, ok := obj["metadata"].(map[string]any); ok {
			md["namespace"] = ns
		}
		res.Namespace = ns
	} else {
		ns = ""
		res.Namespace = ""
	}
	if SecretLooksRedacted(obj) {
		res.Status = http.StatusBadRequest
		res.Error = "secret data is redacted; apply YAML with real values"
		return res
	}
	StripForCreate(obj)
	body, err := json.Marshal(obj)
	if err != nil {
		res.Status = http.StatusBadRequest
		res.Error = "marshal object"
		return res
	}
	listPath, err := APIPath(kind, ns, "")
	if err != nil {
		res.Status = http.StatusBadRequest
		res.Error = err.Error()
		return res
	}
	code, raw, err := g.Do(ctx, row, CallOptions{Method: http.MethodPost, Path: listPath, Body: body})
	if err != nil && code == 0 {
		res.Status = http.StatusBadGateway
		res.Error = err.Error()
		return res
	}
	if code == http.StatusConflict {
		named, err := APIPath(kind, ns, name)
		if err != nil {
			res.Status = http.StatusBadRequest
			res.Error = err.Error()
			return res
		}
		_, existing, getErr := g.Do(ctx, row, CallOptions{Method: http.MethodGet, Path: named})
		if getErr == nil {
			SetResourceVersion(obj, ObjectResourceVersion(existing))
			body, _ = json.Marshal(obj)
		}
		code, raw, err = g.Do(ctx, row, CallOptions{Method: http.MethodPut, Path: named, Body: body})
		res.Verb = "update"
		if err != nil && code == 0 {
			res.Status = http.StatusBadGateway
			res.Error = err.Error()
			return res
		}
	}
	res.Status = code
	if err != nil && len(raw) == 0 {
		res.Error = err.Error()
	} else if code >= 300 {
		res.Error = k8sStatusMessage(raw)
	}
	if len(raw) > 0 && json.Valid(raw) {
		res.Object = json.RawMessage(raw)
	}
	return res
}

func (g *Gateway) ReplaceObject(ctx context.Context, row sessionsvc.Session, obj map[string]any) (int, []byte, error) {
	apiVersion, kindName, ns, name := ManifestIdentity(obj)
	if name == "" || kindName == "" {
		return http.StatusBadRequest, nil, fmt.Errorf("kind and metadata.name required")
	}
	kind, err := LookupKindFromGVK(apiVersion, kindName)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	if kind.Namespaced && ns == "" {
		return http.StatusBadRequest, nil, fmt.Errorf("namespace required")
	}
	if SecretLooksRedacted(obj) {
		return http.StatusBadRequest, nil, fmt.Errorf("secret data is redacted; apply YAML with real values")
	}
	delete(obj, "status")
	if md, ok := obj["metadata"].(map[string]any); ok {
		delete(md, "managedFields")
	}
	body, err := json.Marshal(obj)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	path, err := APIPath(kind, ns, name)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	return g.Do(ctx, row, CallOptions{Method: http.MethodPut, Path: path, Body: body})
}

func (g *Gateway) DeleteObject(ctx context.Context, row sessionsvc.Session, resource, group, namespace, name string) (int, []byte, error) {
	kind, err := LookupKind(resource, group)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return http.StatusBadRequest, nil, fmt.Errorf("name required")
	}
	path, err := APIPath(kind, namespace, name)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	return g.Do(ctx, row, CallOptions{Method: http.MethodDelete, Path: path})
}
