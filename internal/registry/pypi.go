package registry

import (
	"sort"
	"strings"
	"time"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// pypiURL is the base URL for PyPI's JSON API. The endpoint returns package
// metadata including all release files with upload timestamps, which we use
// to derive the package creation time.
const pypiURL = "https://pypi.org/pypi/"

// pypiProject is the subset of the PyPI JSON API document we consume. PyPI does
// not expose download counts in this endpoint, so Downloads stays 0 for PyPI.
// The Releases map is used to find the earliest upload time (creation date).
type pypiProject struct {
	Info struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		Author     string `json:"author"`
		Maintainer string `json:"maintainer"`
		// ProjectURLs maps label -> URL; we only need any one repository link.
		ProjectURLs map[string]string `json:"project_urls"`
	} `json:"info"`
	// Releases maps version -> list of files, each with an upload timestamp. The
	// earliest upload time across all releases is the package creation time.
	Releases map[string][]struct {
		UploadTime time.Time `json:"upload_time_iso_8601"`
	} `json:"releases"`
}

// pypiToInfo normalizes a PyPI project into domain.PackageInfo. Publisher uses
// author first, then maintainer as fallback. Repository is extracted from
// project_urls using deterministic label matching (see sourceURL).
func pypiToInfo(p *pypiProject) *domain.PackageInfo {
	publisher := clean(p.Info.Author)
	if publisher == "" {
		publisher = clean(p.Info.Maintainer)
	}
	created := earliestUpload(p.Releases)
	return &domain.PackageInfo{
		Name:       p.Info.Name,
		Registry:   domain.RegistryPypi,
		Version:    p.Info.Version,
		Publisher:  publisher,
		CreatedAt:  created,
		UpdatedAt:  created, // PyPI JSON lacks a modified field; approximate.
		Repository: sourceURL(p.Info.ProjectURLs),
	}
}

// earliestUpload scans all release files for the minimum upload time. A single
// linear pass keeps this allocation-free and O(n) — sorting is unnecessary for
// finding the minimum.
func earliestUpload(releases map[string][]struct {
	UploadTime time.Time `json:"upload_time_iso_8601"`
}) time.Time {
	var earliest time.Time
	for _, files := range releases {
		for _, f := range files {
			if earliest.IsZero() || f.UploadTime.Before(earliest) {
				earliest = f.UploadTime
			}
		}
	}
	return earliest
}

// sourceKeys are the project_urls labels that denote actual source code, in
// preference order. PyPI lets publishers use arbitrary labels, so we look for
// the meaningful ones first. This deterministic ordering prevents the randomized
// map iteration bug documented in HANDOFF bug #3.
var sourceKeys = []string{"source", "source code", "repository", "code", "github", "homepage"}

// sourceURL picks a repository URL deterministically. The previous implementation
// took whichever key Go's randomized map iteration yielded first, which made the
// NO_SOURCE_REPOSITORY signal — and therefore the threat verdict — unstable between
// runs on the same package. The fix: check preferred labels first, then fall back
// to sorted keys for determinism.
func sourceURL(urls map[string]string) string {
	for _, want := range sourceKeys {
		for k, v := range urls {
			if strings.ToLower(strings.TrimSpace(k)) == want {
				if c := clean(v); c != "" {
					return c
				}
			}
		}
	}
	// Fallback: sorted keys for deterministic output when no preferred label matches.
	keys := make([]string, 0, len(urls))
	for k := range urls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if c := clean(urls[k]); c != "" {
			return c
		}
	}
	return ""
}
