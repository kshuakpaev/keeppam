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
		{"command_denied", map[string]any{"command": "rm -rf /"}, "DENIED rm -rf /"},
		{"dlp", map[string]any{"command": "scp -t /tmp/x"}, "DENIED scp -t /tmp/x"},
		{"risk", map[string]any{"statement": "DROP TABLE t"}, "DENIED DROP TABLE t"},
		{"started", map[string]any{}, "started"},
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
