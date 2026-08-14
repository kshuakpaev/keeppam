package k8sproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/websocket"
)

func TestExecOnceStream(t *testing.T) {
	upg := websocket.Upgrader{
		CheckOrigin:  func(*http.Request) bool { return true },
		Subprotocols: []string{"v4.channel.k8s.io", "v5.channel.k8s.io"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("command") != "id" {
			http.Error(w, "command", 400)
			return
		}
		if r.Header.Get("Authorization") != "Bearer vault" {
			http.Error(w, "auth", 401)
			return
		}
		c, err := upg.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(websocket.BinaryMessage, append([]byte{chanStdout}, []byte("uid=0")...))
		_ = c.WriteMessage(websocket.BinaryMessage, append([]byte{chanError}, []byte(`{"status":"Success"}`)...))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	up := &sessionUpstream{up: &Upstream{Server: u, Token: "vault"}}
	conn, err := dialExec(context.Background(), up, "default", "web", "", []string{"id"}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	res, err := readExecResult(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "uid=0" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestSanitizeCommand(t *testing.T) {
	got := sanitizeCommand([]string{"", "ls", "\x00bad", "ok"})
	if len(got) != 2 || got[0] != "ls" || got[1] != "ok" {
		t.Fatalf("%v", got)
	}
}
