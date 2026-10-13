package session

import "time"

// IdleExpired reports whether last activity is at least idle ago.
// A zero last-activity timestamp is not expired: the next request stamps it.
func IdleExpired(last, now time.Time, idle time.Duration) bool {
	if last.IsZero() || idle <= 0 {
		return false
	}
	return !now.Before(last.Add(idle))
}
