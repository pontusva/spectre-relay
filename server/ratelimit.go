package server

import (
	"sync"
	"time"
)

// rateLimiter is a per-key sliding-window limiter over a fixed 1-minute
// window. Used to bound sealed-sender certificate issuance per authenticated
// user so a client cannot spam the CA signing path. (The Router has its own
// inline per-user limiter for message routing; this is a separate budget so
// cert requests and chat traffic don't starve each other.)
type rateLimiter struct {
	mu       sync.Mutex
	perMin   int
	attempts map[string][]time.Time
}

func newRateLimiter(perMin int) *rateLimiter {
	return &rateLimiter{
		perMin:   perMin,
		attempts: make(map[string][]time.Time),
	}
}

// allow records an attempt for key at time now and reports whether it is
// within the per-minute budget. Expired timestamps are pruned on each call,
// so the map does not grow unboundedly for an active key.
func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-time.Minute)
	xs := l.attempts[key]
	kept := xs[:0]
	for _, t := range xs {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.perMin {
		l.attempts[key] = kept
		return false
	}
	l.attempts[key] = append(kept, now)
	return true
}
