package registry

import (
	"context"
	"testing"
	"time"
)

func TestLimiter_AllowsBurst(t *testing.T) {
	l := NewLimiter(10, 3)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatalf("burst wait %d failed: %v", i, err)
		}
	}
}

func TestLimiter_ContextCancel(t *testing.T) {
	l := NewLimiter(1, 1) // 1 token, 1/sec
	ctx := context.Background()
	if err := l.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	// Bucket empty; a second wait should block until either token refill or cancel.
	cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := l.Wait(cctx); err == nil {
		t.Fatal("expected context deadline error, got nil")
	}
}

func TestLimiter_PenalizeDelays(t *testing.T) {
	l := NewLimiter(100, 5)
	ctx := context.Background()
	if err := l.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	l.Penalize(200 * time.Millisecond)
	start := time.Now()
	if err := l.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Fatalf("penalize did not delay enough: %v", time.Since(start))
	}
}
