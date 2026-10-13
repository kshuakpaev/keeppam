package session

import (
	"testing"
	"time"
)

func TestIdleExpired(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	idle := 5 * time.Minute
	if IdleExpired(time.Time{}, now, idle) {
		t.Fatal("zero last activity must not expire")
	}
	if IdleExpired(now.Add(-4*time.Minute), now, idle) {
		t.Fatal("activity inside the window must not expire")
	}
	if !IdleExpired(now.Add(-5*time.Minute), now, idle) {
		t.Fatal("activity exactly at the timeout must expire")
	}
	if !IdleExpired(now.Add(-30*time.Minute), now, idle) {
		t.Fatal("activity past the timeout must expire")
	}
	if IdleExpired(now.Add(-time.Hour), now, 0) {
		t.Fatal("non-positive idle must not expire")
	}
}
