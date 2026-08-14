package notify

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUsableEmail(t *testing.T) {
	ok := []string{"alice@example.com", "Bob@Corp.KZ"}
	bad := []string{"", "nope", "a@", "@x", "a@ldap.local", "b@oidc.local", "c@saml.local", "a b@x.com"}
	for _, e := range ok {
		if !UsableEmail(e) {
			t.Fatalf("want usable %q", e)
		}
	}
	for _, e := range bad {
		if UsableEmail(e) {
			t.Fatalf("want skip %q", e)
		}
	}
}

func TestBuildMessageUTF8Subject(t *testing.T) {
	raw := string(buildMessage("pam@x", []string{"a@x"}, "Новый JIT-запрос", "тело\nстрока"))
	if strings.Contains(raw, "\nНовый") && !strings.Contains(raw, "=?UTF-8?B?") {
		t.Fatalf("subject not encoded: %s", raw)
	}
	if !strings.Contains(strings.ToUpper(raw), "=?UTF-8?B?") {
		t.Fatalf("missing rfc2047: %s", raw)
	}
	if strings.Contains(raw, "From: pam@x\r\nFrom:") {
		t.Fatal("dup from")
	}
	if strings.Contains(raw, "Subject: Новый") {
		t.Fatal("raw unicode in header")
	}
	if !strings.Contains(raw, "тело\r\nстрока") {
		t.Fatalf("body crlf: %q", raw)
	}
}

func TestSanitizeHeader(t *testing.T) {
	if got := sanitizeHeader("a@x\r\nBcc: evil@x"); got != "a@xBcc: evil@x" {
		t.Fatalf("%q", got)
	}
}

func TestSendMailNone(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var got struct {
		mu   sync.Mutex
		from string
		to   string
		data string
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		write := func(s string) { _, _ = io.WriteString(conn, s) }
		write("220 test ESMTP\r\n")
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			u := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(u, "EHLO"), strings.HasPrefix(u, "HELO"):
				write("250-localhost\r\n250 HELP\r\n")
			case strings.HasPrefix(u, "MAIL FROM:"):
				got.mu.Lock()
				got.from = strings.TrimSpace(line)
				got.mu.Unlock()
				write("250 ok\r\n")
			case strings.HasPrefix(u, "RCPT TO:"):
				got.mu.Lock()
				got.to = strings.TrimSpace(line)
				got.mu.Unlock()
				write("250 ok\r\n")
			case u == "DATA":
				write("354 go\r\n")
				var b strings.Builder
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				got.mu.Lock()
				got.data = b.String()
				got.mu.Unlock()
				write("250 queued\r\n")
			case u == "QUIT":
				write("221 bye\r\n")
				return
			default:
				write("250 ok\r\n")
			}
		}
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	err = SendMail(SMTPConfig{
		Host: "127.0.0.1", Port: port, TLS: "none", From: "keeppam@local", Timeout: 3 * time.Second,
	}, []string{"alice@example.com"}, "JIT approved", "asset prod-db")
	if err != nil {
		t.Fatal(err)
	}
	<-done
	got.mu.Lock()
	defer got.mu.Unlock()
	if !strings.Contains(got.from, "keeppam@local") || !strings.Contains(got.to, "alice@example.com") {
		t.Fatalf("envelope from=%q to=%q", got.from, got.to)
	}
	if !strings.Contains(got.data, "Subject: JIT approved") || !strings.Contains(got.data, "asset prod-db") {
		t.Fatalf("data %q", got.data)
	}
}

func TestNormalizeSMTPTLS(t *testing.T) {
	got, err := normalizeSMTPTLS(" TLS ")
	if err != nil || got != "tls" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := normalizeSMTPTLS("ssl"); err == nil {
		t.Fatal("expected error")
	}
	got, err = normalizeSMTPTLS("")
	if err != nil || got != "starttls" {
		t.Fatalf("default %q %v", got, err)
	}
}

func TestSendMailNoRecipients(t *testing.T) {
	err := SendMail(SMTPConfig{Host: "127.0.0.1", From: "a@x"}, []string{"x@ldap.local"}, "s", "b")
	if err == nil {
		t.Fatal("expected error")
	}
}
