package notify

import (
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
	"unicode"
)

type SMTPConfig struct {
	Host     string
	Port     int
	TLS      string
	Insecure bool
	Username string
	Password string
	From     string
	Timeout  time.Duration
}

var sendMailFn = SendMail

func UsableEmail(raw string) bool {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" || strings.ContainsAny(email, " \t\r\n") {
		return false
	}
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return false
	}
	switch email[at+1:] {
	case "ldap.local", "oidc.local", "saml.local":
		return false
	}
	return true
}

func SendMail(cfg SMTPConfig, to []string, subject, body string) error {
	from := strings.TrimSpace(cfg.From)
	host := strings.TrimSpace(cfg.Host)
	if host == "" || from == "" {
		return fmt.Errorf("smtp host and from required")
	}
	var rcpt []string
	for _, a := range to {
		if UsableEmail(a) {
			rcpt = append(rcpt, strings.TrimSpace(a))
		}
	}
	if len(rcpt) == 0 {
		return fmt.Errorf("no recipients")
	}
	port := cfg.Port
	if port <= 0 {
		port = 587
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.TLS))
	if mode == "" {
		mode = "starttls"
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	tlsCfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: cfg.Insecure, //nolint:gosec // optional on-prem self-signed relay
		MinVersion:         tls.VersionTLS12,
	}
	dialer := net.Dialer{Timeout: timeout}
	var (
		conn net.Conn
		err  error
	)
	if mode == "tls" {
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	if mode == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("STARTTLS not supported")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if strings.TrimSpace(cfg.Username) != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, a := range rcpt {
		if err := c.Rcpt(a); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(buildMessage(from, rcpt, subject, body)); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func buildMessage(from string, to []string, subject, body string) []byte {
	from = sanitizeHeader(from)
	subj := encodeSubject(sanitizeHeader(subject))
	var rcpts []string
	for _, a := range to {
		rcpts = append(rcpts, sanitizeHeader(a))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(rcpts, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subj)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

func encodeSubject(s string) string {
	if isASCII(s) {
		return s
	}
	return mime.BEncoding.Encode("UTF-8", s)
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return strings.TrimSpace(s)
}

func normalizeSMTPTLS(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "starttls", nil
	}
	switch v {
	case "starttls", "tls", "none":
		return v, nil
	default:
		return "", fmt.Errorf("smtp_tls must be starttls, tls or none")
	}
}
