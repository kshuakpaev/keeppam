package discovery

import "testing"

func TestParsePasswd(t *testing.T) {
	raw := []byte(`root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
app:x:1001:1001::/home/app:/bin/sh
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
`)
	users := parsePasswd(raw)
	names := map[string]passwdUser{}
	for _, u := range users {
		names[u.Name] = u
	}
	if _, ok := names["root"]; !ok || !names["root"].Privileged {
		t.Fatalf("root missing/privileged: %+v", names["root"])
	}
	if _, ok := names["ubuntu"]; !ok {
		t.Fatal("ubuntu missing")
	}
	if _, ok := names["daemon"]; ok {
		t.Fatal("nologin daemon should be skipped")
	}
	if _, ok := names["sshd"]; ok {
		t.Fatal("sshd nologin should be skipped")
	}
}
