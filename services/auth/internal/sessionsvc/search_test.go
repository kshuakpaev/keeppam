package sessionsvc

import "testing"

func TestEventSnippet(t *testing.T) {
	cases := []struct {
		typ  string
		p    map[string]any
		want string
	}{
		{"sql", map[string]any{"statement": "SELECT 1"}, "SELECT 1"},
		{"sql_denied", map[string]any{"statement": "DROP TABLE t", "reason": "ddl"}, "DENIED DROP TABLE t (ddl)"},
		{"k8s", map[string]any{"verb": "get", "resource": "pods", "namespace": "prod", "name": "web", "status": "200"}, "get pods prod/web → 200"},
		{"command", map[string]any{"command": "systemctl restart nginx"}, "systemctl restart nginx"},
		{"output", map[string]any{"line": "secret.txt"}, "secret.txt"},
		{"keystroke", map[string]any{"line": "notepad"}, "notepad"},
		{"screen_text", map[string]any{"line": "Password123"}, "Password123"},
		{"command_approved", map[string]any{"command": "rm -rf /tmp/x"}, "APPROVED rm -rf /tmp/x"},
		{"command_denied", map[string]any{"command": "rm -rf /"}, "DENIED rm -rf /"},
		{"dlp", map[string]any{"command": "scp -t /tmp/x"}, "DENIED scp -t /tmp/x"},
		{"risk", map[string]any{"statement": "DROP TABLE t"}, "DENIED DROP TABLE t"},
		{"http_denied", map[string]any{"method": "DELETE", "path": "/admin", "reason": "http denied by ACL: DELETE /admin"}, "DENIED DELETE /admin (http denied by ACL: DELETE /admin)"},
		{"app_denied", map[string]any{"method": "DELETE", "path": "/api/customers/1", "reason": "app object denied: customer.delete"}, "DENIED DELETE /api/customers/1 (app object denied: customer.delete)"},
		{"app_approved", map[string]any{"method": "GET", "path": "/api/customers/export", "object": "customer.export"}, "APPROVED GET /api/customers/export (customer.export)"},
		{"egress", map[string]any{"host": "10.1.2.9", "port": 5432}, "10.1.2.9:5432"},
		{"egress_denied", map[string]any{"host": "8.8.8.8", "port": 53, "reason": "ssh egress destination not allowed"}, "DENIED 8.8.8.8:53 (ssh egress destination not allowed)"},
		{"file_transfer", map[string]any{"filename": "secret.bin", "protocol": "scp", "direction": "upload"}, "scp upload secret.bin"},
	}
	for _, tc := range cases {
		got := EventSnippet(tc.typ, tc.p)
		if got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.typ, got, tc.want)
		}
	}
}

func TestLikePatternEscapes(t *testing.T) {
	if got := likePattern(`a%b_c\d`); got != `%a\%b\_c\\d%` {
		t.Fatalf("got %q", got)
	}
}
