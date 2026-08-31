// Package registry contains the public registry adapters used by depwatch. Each
// adapter knows how to query one ecosystem (npm, PyPI, crates.io) and return a
// normalized domain.PackageInfo. The adapter pattern keeps registry-specific
// quirks (different JSON shapes, download count endpoints, User-Agent policies)
// isolated from the rest of the system.
//
// The Registry interface lives here alongside its implementations because the
// family is cohesive: the scanner needs polymorphic dispatch over exactly these
// adapters. Defining the contract next to the implementations keeps the shared
// type and the code that satisfies it in one place.
//
// Rate limiting: each adapter gets its own token-bucket Limiter tuned to the
// registry's documented rate limits. This prevents 429s on shared public
// infrastructure while keeping small inventories fast.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// userAgent identifies depwatch to registries. crates.io in particular rejects
// requests without a User-Agent, and identifying ourselves is good registry
// citizenship. The format follows convention: name/version (+homepage).
const userAgent = "depwatch/0.1 (+https://github.com/yourpwnguy/depwatch)"

// Registry abstracts a single public package registry. Implementations must be
// safe for concurrent use by the scan pipeline's worker pool. The contract is:
//
//   - Name returns the registry identifier (npm, pypi, crates)
//   - Query fetches metadata for a single package name
//   - (nil, nil) means the package does not exist (HTTP 404)
//   - Non-nil error means transport or unexpected failure
//   - A timeout or registry outage MUST surface as an error, never as "not found"
//
// The scanner treats errors as partial results, not as evidence of safety — a
// failing registry means we can't verify a package, not that it's safe.
type Registry interface {
	Name() domain.RegistryName
	Query(ctx context.Context, name string) (*domain.PackageInfo, error)
}

// New constructs the adapter for the named registry, including a per-registry
// rate limiter. Unknown names return an error so misconfiguration fails fast
// rather than silently skipping a registry.
func New(name domain.RegistryName, timeout time.Duration, retries int) (Registry, error) {
	lim := newLimiter(name)
	switch name {
	case domain.RegistryNpm:
		return &npmAdapter{lim: lim, timeout: timeout, retries: retries}, nil
	case domain.RegistryPypi:
		return &httpRegistry{lim: lim, base: pypiURL, suffix: "/json", name: name, timeout: timeout, retries: retries}, nil
	case domain.RegistryCrates:
		return &cratesRegistry{lim: lim, timeout: timeout, retries: retries}, nil
	default:
		return nil, fmt.Errorf("registry %q not supported", name)
	}
}

// newLimiter returns a token-bucket limiter tuned per registry. Conservatism here
// prevents 429s on shared public infrastructure; small inventories finish quickly
// regardless. crates.io documents stricter limits, so it is throttled the hardest.
func newLimiter(name domain.RegistryName) *Limiter {
	switch name {
	case domain.RegistryCrates:
		return NewLimiter(1.5, 3)
	case domain.RegistryNpm:
		return NewLimiter(4, 6)
	case domain.RegistryPypi:
		return NewLimiter(4, 6)
	default:
		return NewLimiter(2, 4)
	}
}

// httpRegistry is a reusable JSON-fetching adapter for registries that expose a
// simple GET endpoint returning package metadata. PyPI fits this shape; npm needs
// a second download-count call and crates.io needs a custom User-Agent, so each
// of those has its own adapter type.
type httpRegistry struct {
	lim     *Limiter
	base    string
	suffix  string
	name    domain.RegistryName
	timeout time.Duration
	retries int
}

func (r *httpRegistry) Name() domain.RegistryName { return r.name }

func (r *httpRegistry) Query(ctx context.Context, name string) (*domain.PackageInfo, error) {
	var p pypiProject
	if err := getJSON(ctx, r.timeout, r.retries, r.lim, r.base+name+r.suffix, nil, &p); err != nil {
		return nil, err
	}
	return pypiToInfo(&p), nil
}

// getJSON performs a GET with context timeout, rate limiting, retries, and 404
// handling. On 404 it returns (nil, nil) so callers can treat absence as "no
// collision". A 429/5xx triggers a backoff and a limiter penalty, then a retry;
// exhausted retries return the last error so the caller marks the lookup partial.
//
// modify, if non-nil, may set request headers (e.g. crates.io's User-Agent
// requirement). The response body is capped at 4 MiB to prevent memory exhaustion
// from a misbehaving registry.
func getJSON(ctx context.Context, timeout time.Duration, retries int, lim *Limiter, url string, modify func(*http.Request), out any) error {
	client := &http.Client{Timeout: timeout}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if lim != nil {
			if err := lim.Wait(ctx); err != nil {
				return err
			}
		}
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff(attempt)):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", userAgent)
		if modify != nil {
			modify(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		switch resp.StatusCode {
		case http.StatusNotFound:
			resp.Body.Close()
			return nil // package does not exist
		case http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
			resp.Body.Close()
			if lim != nil {
				lim.Penalize(15 * time.Second)
			}
			lastErr = fmt.Errorf("registry temporary error: %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("registry %s returned %d", url, resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // cap at 4 MiB
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("read response: %w", err)
		}
		if err := json.Unmarshal(body, out); err != nil {
			// A truncated or malformed body on a 200 is usually a transient
			// transport glitch, so retry rather than failing the whole lookup.
			lastErr = fmt.Errorf("decode response: %w", err)
			continue
		}
		return nil
	}
	return lastErr
}

// backoff returns the wait duration before retry attempt (1-indexed). Linear with
// a 500ms step keeps the scanner polite without exponential blow-up. For 3 retries
// this means: 500ms, 1s, 1.5s — fast enough for transient errors, polite enough
// for a struggling registry.
func backoff(attempt int) time.Duration {
	return time.Duration(attempt) * 500 * time.Millisecond
}

// placeholders are literal strings registries emit in place of omitting a field.
// PyPI in particular returns "UNKNOWN" or "None" for a missing author or repository,
// and treating those as real values corrupts the threat assessment: a package would
// appear to have a published source when it does not.
var placeholders = map[string]bool{
	"": true, "unknown": true, "none": true, "null": true, "n/a": true, "-": true,
}

// clean normalizes a registry-reported metadata string, returning "" when the
// value is absent or a known placeholder. Absence is itself a signal (it feeds
// NO_SOURCE_REPOSITORY, UNVERIFIED_PUBLISHER), so it must be represented as
// absence rather than as text.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if placeholders[strings.ToLower(s)] {
		return ""
	}
	return s
}
