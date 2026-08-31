package registry

import (
	"context"
	"sync"
	"time"
)

// Limiter is a token-bucket rate limiter. Wait blocks until a token is available
// or the context is cancelled. It is safe for concurrent use by many goroutines.
//
// Each enabled registry gets its own Limiter so a single slow or rate-limited
// registry cannot starve the others. The bucket starts full (burst capacity) and
// refills at rate tokens per second.
type Limiter struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64 // tokens per second
	last     time.Time
}

// NewLimiter creates a limiter allowing rate tokens per second with the given
// burst capacity. A burst of at least 1 is enforced.
func NewLimiter(ratePerSec float64, burst int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	if ratePerSec <= 0 {
		ratePerSec = 1
	}
	return &Limiter{
		tokens:   float64(burst),
		capacity: float64(burst),
		rate:     ratePerSec,
		last:     time.Now(),
	}
}

// Wait blocks until one token is available or ctx is done. It returns ctx.Err()
// if the context is cancelled while waiting.
func (l *Limiter) Wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.last).Seconds()
		l.tokens += elapsed * l.rate
		if l.tokens > l.capacity {
			l.tokens = l.capacity
		}
		l.last = now
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		// No token yet: sleep until one is expected, then retry.
		wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()

		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Penalize drains the bucket and pushes the refill clock forward by cooldown,
// used after a 429 response to back off aggressively without a full stop. The
// caller should later resume normal Wait calls; the bucket naturally refills.
func (l *Limiter) Penalize(cooldown time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokens = 0
	l.last = time.Now().Add(cooldown)
}
