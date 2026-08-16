package k8sproxy

import "testing"

func TestParseAPIPath(t *testing.T) {
	cases := []struct {
		method, path string
		watch        bool
		verb, res, ns, name, sub string
	}{
		{"GET", "/api/v1/namespaces", false, "list", "namespaces", "", "", ""},
		{"GET", "/api/v1/namespaces/prod/pods", false, "list", "pods", "prod", "", ""},
		{"GET", "/api/v1/namespaces/prod/pods/web", false, "get", "pods", "prod", "web", ""},
		{"GET", "/api/v1/namespaces/prod/pods/web/log", false, "get", "pods", "prod", "web", "log"},
		{"POST", "/api/v1/namespaces/prod/pods/web/exec", false, "create", "pods", "prod", "web", "exec"},
		{"GET", "/apis/apps/v1/namespaces/prod/deployments", false, "list", "deployments", "prod", "", ""},
		{"GET", "/api/v1/pods", true, "watch", "pods", "", "", ""},
		{"DELETE", "/api/v1/namespaces/prod/secrets/x", false, "delete", "secrets", "prod", "x", ""},
	}
	for _, tc := range cases {
		c := ParseAPIPath(tc.method, tc.path, tc.watch)
		if c.Verb != tc.verb || c.Resource != tc.res || c.Namespace != tc.ns || c.Name != tc.name || c.Subresource != tc.sub {
			t.Fatalf("%s %s => %+v want verb=%s res=%s ns=%s name=%s sub=%s",
				tc.method, tc.path, c, tc.verb, tc.res, tc.ns, tc.name, tc.sub)
		}
	}
	if !ParseAPIPath("POST", "/api/v1/namespaces/n/pods/p/exec", false).Denied() {
		t.Fatal("exec should be denied")
	}
	if !ParseAPIPath("GET", "/api/v1/namespaces/n/pods/p/attach", false).Denied() {
		t.Fatal("attach should be denied")
	}
	if !ParseAPIPath("GET", "/api/v1/namespaces/n/pods/p/portforward", false).Denied() {
		t.Fatal("portforward should be denied")
	}
}
