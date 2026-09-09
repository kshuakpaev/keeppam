package httpapi

import (
	"net/http"
	"testing"
)

func TestClientFacingHost(t *testing.T) {
	req := func(host, xfh string) *http.Request {
		r := &http.Request{Host: host, Header: http.Header{}}
		if xfh != "" {
			r.Header.Set("X-Forwarded-Host", xfh)
		}
		return r
	}
	cases := []struct {
		name, cfg, host, xfh, want string
	}{
		{"explicit fqdn", "pam.example.com", "10.0.0.5:5173", "", "pam.example.com"},
		{"prefer request over localhost cfg", "localhost", "10.0.0.5:5173", "", "10.0.0.5"},
		{"prefer request over 127", "127.0.0.1", "pam.corp", "", "pam.corp"},
		{"xfh over host", "localhost", "api:8080", "10.1.2.3:5173", "10.1.2.3"},
		{"empty cfg uses request", "", "10.0.0.5:8080", "", "10.0.0.5"},
		{"both loopback keep cfg", "localhost", "127.0.0.1:5173", "", "localhost"},
		{"off uses request", "off", "10.0.0.5", "", "10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clientFacingHost(tc.cfg, req(tc.host, tc.xfh))
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
