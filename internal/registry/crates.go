package registry

import (
	"context"
	"net/http"
	"time"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// cratesURL is the crates.io API endpoint for crate metadata. The API requires
// a descriptive User-Agent header; without it the request is rejected.
const cratesURL = "https://crates.io/api/v1/crates/"

// cratesRegistry queries crates.io. Unlike the generic httpRegistry (used for
// PyPI), this adapter sets a custom User-Agent header because crates.io policy
// requires clients to identify themselves. The adapter also extracts download
// counts, which crates.io provides in the crate metadata response.
type cratesRegistry struct {
	lim     *Limiter
	timeout time.Duration
	retries int
}

func (r *cratesRegistry) Name() domain.RegistryName { return domain.RegistryCrates }

// Query fetches crate metadata from crates.io. The response JSON has a "crate"
// wrapper object containing the fields we need. Repository URL is cleaned
// through the shared clean() function to normalize placeholder values.
func (r *cratesRegistry) Query(ctx context.Context, name string) (*domain.PackageInfo, error) {
	var resp struct {
		Crate struct {
			ID         string    `json:"id"`
			MaxVersion string    `json:"max_version"`
			CreatedAt  time.Time `json:"created_at"`
			UpdatedAt  time.Time `json:"updated_at"`
			Downloads  int64     `json:"downloads"`
			Repository string    `json:"repository"`
		} `json:"crate"`
	}
	modify := func(req *http.Request) {
		// crates.io policy: identify the client (a default UA is also set in
		// getJSON, but we restate it here to be explicit and policy-compliant).
		req.Header.Set("User-Agent", userAgent)
	}
	if err := getJSON(ctx, r.timeout, r.retries, r.lim, cratesURL+name, modify, &resp); err != nil {
		return nil, err
	}
	c := resp.Crate
	return &domain.PackageInfo{
		Name:       c.ID,
		Registry:   domain.RegistryCrates,
		Version:    c.MaxVersion,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
		Downloads:  c.Downloads,
		Repository: clean(c.Repository),
	}, nil
}
