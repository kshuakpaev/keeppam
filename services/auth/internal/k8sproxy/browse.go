package k8sproxy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type ResourceKind struct {
	Name       string `json:"name"`
	Resource   string `json:"resource"`
	Group      string `json:"group,omitempty"`
	Version    string `json:"version"`
	Namespaced bool   `json:"namespaced"`
}

func Catalog() []ResourceKind {
	return []ResourceKind{
		{Name: "Namespaces", Resource: "namespaces", Version: "v1", Namespaced: false},
		{Name: "Pods", Resource: "pods", Version: "v1", Namespaced: true},
		{Name: "Deployments", Resource: "deployments", Group: "apps", Version: "v1", Namespaced: true},
		{Name: "ReplicaSets", Resource: "replicasets", Group: "apps", Version: "v1", Namespaced: true},
		{Name: "StatefulSets", Resource: "statefulsets", Group: "apps", Version: "v1", Namespaced: true},
		{Name: "DaemonSets", Resource: "daemonsets", Group: "apps", Version: "v1", Namespaced: true},
		{Name: "Jobs", Resource: "jobs", Group: "batch", Version: "v1", Namespaced: true},
		{Name: "CronJobs", Resource: "cronjobs", Group: "batch", Version: "v1", Namespaced: true},
		{Name: "Services", Resource: "services", Version: "v1", Namespaced: true},
		{Name: "Ingresses", Resource: "ingresses", Group: "networking.k8s.io", Version: "v1", Namespaced: true},
		{Name: "ConfigMaps", Resource: "configmaps", Version: "v1", Namespaced: true},
		{Name: "Secrets", Resource: "secrets", Version: "v1", Namespaced: true},
		{Name: "PersistentVolumeClaims", Resource: "persistentvolumeclaims", Version: "v1", Namespaced: true},
	}
}

func LookupKind(resource, group string) (ResourceKind, error) {
	resource = strings.ToLower(strings.TrimSpace(resource))
	group = strings.ToLower(strings.TrimSpace(group))
	if alias, ok := resourceAlias[resource]; ok {
		resource = alias
	}
	for _, k := range Catalog() {
		if k.Resource == resource && strings.ToLower(k.Group) == group {
			return k, nil
		}
	}
	if group == "" {
		for _, k := range Catalog() {
			if k.Resource == resource {
				return k, nil
			}
		}
	}
	return ResourceKind{}, fmt.Errorf("unknown resource %s", resource)
}

var resourceAlias = map[string]string{
	"ns": "namespaces", "namespace": "namespaces",
	"po": "pods", "pod": "pods",
	"deploy": "deployments", "deployment": "deployments",
	"rs": "replicasets", "replicaset": "replicasets",
	"sts": "statefulsets", "statefulset": "statefulsets",
	"ds": "daemonsets", "daemonset": "daemonsets",
	"job": "jobs", "cj": "cronjobs", "cronjob": "cronjobs",
	"svc": "services", "service": "services",
	"ing": "ingresses", "ingress": "ingresses",
	"cm": "configmaps", "configmap": "configmaps",
	"secret": "secrets",
	"pvc": "persistentvolumeclaims", "persistentvolumeclaim": "persistentvolumeclaims",
}

func LookupKindFromGVK(apiVersion, kind string) (ResourceKind, error) {
	group, _ := SplitAPIVersion(apiVersion)
	return LookupKind(kind, group)
}

func SplitAPIVersion(apiVersion string) (group, version string) {
	apiVersion = strings.TrimSpace(apiVersion)
	if apiVersion == "" {
		return "", "v1"
	}
	i := strings.LastIndex(apiVersion, "/")
	if i < 0 {
		return "", apiVersion
	}
	return apiVersion[:i], apiVersion[i+1:]
}

func APIPath(kind ResourceKind, namespace, name string) (string, error) {
	ns := strings.TrimSpace(namespace)
	n := strings.TrimSpace(name)
	if kind.Namespaced && ns == "" && n == "" {
		return "", fmt.Errorf("namespace required")
	}
	prefix := "/api/" + kind.Version
	if kind.Group != "" {
		prefix = "/apis/" + kind.Group + "/" + kind.Version
	}
	if kind.Namespaced {
		p := prefix + "/namespaces/" + url.PathEscape(ns) + "/" + kind.Resource
		if n != "" {
			p += "/" + url.PathEscape(n)
		}
		return p, nil
	}
	p := prefix + "/" + kind.Resource
	if n != "" {
		p += "/" + url.PathEscape(n)
	}
	return p, nil
}

type BrowseItem struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Status    string `json:"status,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

func SummarizeList(raw []byte) []BrowseItem {
	var m map[string]any
	if err := jsonUnmarshal(raw, &m); err != nil {
		return nil
	}
	kind, _ := m["kind"].(string)
	if strings.HasSuffix(kind, "List") {
		arr, _ := m["items"].([]any)
		out := make([]BrowseItem, 0, len(arr))
		for _, it := range arr {
			mm, ok := it.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, summarizeObj(mm))
		}
		return out
	}
	return []BrowseItem{summarizeObj(m)}
}

func summarizeObj(m map[string]any) BrowseItem {
	it := BrowseItem{Kind: str(m["kind"])}
	if md, ok := m["metadata"].(map[string]any); ok {
		it.Name = str(md["name"])
		it.Namespace = str(md["namespace"])
		it.CreatedAt = str(md["creationTimestamp"])
	}
	if st, ok := m["status"].(map[string]any); ok {
		if p := str(st["phase"]); p != "" {
			it.Status = p
		} else if conds, ok := st["conditions"].([]any); ok {
			for _, c := range conds {
				cm, ok := c.(map[string]any)
				if !ok {
					continue
				}
				if str(cm["type"]) == "Ready" || str(cm["type"]) == "Available" {
					it.Status = str(cm["type"]) + "=" + str(cm["status"])
					break
				}
			}
		}
	}
	return it
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func jsonUnmarshal(raw []byte, v any) error {
	return json.Unmarshal(raw, v)
}
