package guacd

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// Parse splits KEEPPAM_GUACD_ADDR: "host:4822" or "a:4822,b:4822".
// Empty / "off" → nil (guacd disabled).
func Parse(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "off") {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" || strings.EqualFold(p, "off") {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Dial connects to the next healthy address (round-robin, skip failures).
func Dial(addrs []string, timeout time.Duration) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("guacd is not configured")
	}
	if len(addrs) == 1 {
		c, err := net.DialTimeout("tcp", addrs[0], timeout)
		if err != nil {
			return nil, fmt.Errorf("guacd dial: %w", err)
		}
		return c, nil
	}
	start := int(rr.Add(1))
	var last error
	for i := 0; i < len(addrs); i++ {
		addr := addrs[(start+i)%len(addrs)]
		c, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			return c, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("guacd dial failed")
	}
	return nil, fmt.Errorf("guacd dial: %w", last)
}

var rr atomic.Uint32
