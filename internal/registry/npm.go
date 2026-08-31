package registry

import (
	"context"
	"strings"
	"time"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// npm registry endpoints. The packument endpoint returns full metadata; the
// downloads endpoint returns last-month download counts as a separate call.
const npmRegistryURL = "https://registry.npmjs.org/"
const npmDownloadsURL = "https://api.npmjs.org/downloads/point/last-month/"

// npmPackument is the subset of the npm registry document we consume. The full
// packument is large (includes all version tarballs, READMEs, etc.); we decode
// only what we need to avoid unnecessary allocation and memory pressure.
type npmPackument struct {
	Name     string `json:"name"`
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
	Time struct {
		Created  time.Time `json:"created"`
		Modified time.Time `json:"modified"`
	} `json:"time"`
	Versions map[string]struct {
		Maintainers []struct {
			Name string `json:"name"`
		} `json:"maintainers"`
	} `json:"versions"`
}

// npmAdapter queries npm and additionally fetches the last-month download count,
// which feeds the LOW_REPUTATION / WIDELY_USED / ESTABLISHED_USAGE signals.
// The download call is best-effort — a failure yields 0 and is ignored by the
// caller because the count is only a signal, not a blocker.
type npmAdapter struct {
	lim     *Limiter
	timeout time.Duration
	retries int
}

func (a *npmAdapter) Name() domain.RegistryName { return domain.RegistryNpm }

// Query fetches the npm packument and the download count. Scoped names (e.g.
// "@acme/scheduler") are URL-encoded as "%2F" for the registry API.
func (a *npmAdapter) Query(ctx context.Context, name string) (*domain.PackageInfo, error) {
	encoded := strings.ReplaceAll(name, "/", "%2F")
	var p npmPackument
	if err := getJSON(ctx, a.timeout, a.retries, a.lim, npmRegistryURL+encoded, nil, &p); err != nil {
		return nil, err
	}
	info := npmToInfo(&p)
	info.Downloads = npmDownloads(ctx, a.timeout, a.retries, a.lim, name)
	return info, nil
}

// npmToInfo normalizes a packument into domain.PackageInfo. Publisher is taken
// from the latest version's maintainers list — npm packages often have multiple
// maintainers but we use the first for consistency.
func npmToInfo(p *npmPackument) *domain.PackageInfo {
	latest := p.DistTags.Latest
	publisher := ""
	if v, ok := p.Versions[latest]; ok && len(v.Maintainers) > 0 {
		publisher = v.Maintainers[0].Name
	}
	return &domain.PackageInfo{
		Name:      p.Name,
		Registry:  domain.RegistryNpm,
		Version:   latest,
		Publisher: clean(publisher),
		CreatedAt: p.Time.Created,
		UpdatedAt: p.Time.Modified,
	}
}

// npmDownloads fetches the last-month download count. A failure (registry down,
// package absent from the downloads API) yields 0 and is ignored by the caller,
// because the download count is only a LOW-severity signal. This best-effort
// approach keeps the scanner resilient to partial npm outages.
func npmDownloads(ctx context.Context, timeout time.Duration, retries int, lim *Limiter, name string) int64 {
	var resp struct {
		Downloads int64 `json:"downloads"`
	}
	encoded := strings.ReplaceAll(name, "/", "%2F")
	if err := getJSON(ctx, timeout, retries, lim, npmDownloadsURL+encoded, nil, &resp); err != nil {
		return 0
	}
	return resp.Downloads
}
