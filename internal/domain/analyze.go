package domain

import (
	"fmt"
	"time"
)

// Analyze turns a collision into an explainable Assessment: the signals that fired,
// the aggregate risk (consumed by alerting and the CI gate), and a threat judgement.
//
// The function is pure: it takes the collision, the previously persisted entry (nil on
// first observation), the current time, and the organization name, and returns the
// assessment. No clock, no I/O, no global state — the security logic stays in one
// auditable, deterministic place.
//
// Two kinds of signal are emitted and both are kept:
//
//   - aggravating: recent publication, missing repository or publisher, no installs,
//     an org-shaped name, or appearing after we started watching. These argue squat.
//   - mitigating: age, popularity, a published source repository, a named publisher,
//     or a generic dictionary name. These argue coincidence.
//
// Keeping mitigating signals as first-class output is the point: the tool must be able
// to say "this is a collision, but it looks legitimate, and here is why".
func Analyze(c *Collision, prev *ScanEntry, now time.Time, org string) Assessment {
	a := Assessment{}
	p := c.Public

	switch c.Type {
	case CollisionExact:
		a.add(0, Signal{Code: "EXACT_NAME_COLLISION", Severity: SigHigh,
			Message: "Public package shares an exact name with an internal package"})
	case CollisionNamespace:
		a.add(0, Signal{Code: "NAMESPACE_COLLISION", Severity: SigHigh,
			Message: "Public package shares the internal package scope"})
	}

	// --- naming: who would plausibly own this name -------------------------------
	switch {
	case IsOrgSpecificName(c.Internal.Name, org):
		a.add(wOrgSpecificName, Signal{Code: "ORG_SPECIFIC_NAME", Severity: SigHigh,
			Message: "Name is specific to this organization and should not exist publicly",
			Detail:  "org " + org})
	case IsGenericName(c.Internal.Name):
		a.add(wGenericName, Signal{Code: "GENERIC_NAME", Severity: SigLow,
			Message: "Name is a common generic term, so a public package is likely unrelated"})
	}

	// --- age: brand-new packages are the classic squat tell ----------------------
	if !p.CreatedAt.IsZero() {
		age := now.Sub(p.CreatedAt)
		days := int(age.Hours() / 24)
		switch {
		case age <= brandNewAge:
			a.add(wBrandNew, Signal{Code: "NEWLY_REGISTERED", Severity: SigHigh,
				Message: "Public package was created within the last 30 days",
				Detail:  fmt.Sprintf("%dd old", days)})
		case age <= recentAge:
			a.add(wRecent, Signal{Code: "RECENTLY_REGISTERED", Severity: SigMed,
				Message: "Public package was created within the last 90 days",
				Detail:  fmt.Sprintf("%dd old", days)})
		case age <= youngAge:
			a.add(wYoung, Signal{Code: "YOUNG_PACKAGE", Severity: SigLow,
				Message: "Public package is less than a year old",
				Detail:  fmt.Sprintf("%dd old", days)})
		case age >= veryOldAge:
			a.add(wVeryOld, Signal{Code: "LONG_ESTABLISHED", Severity: SigLow,
				Message: "Public package has existed for over five years",
				Detail:  fmt.Sprintf("%dd old", days)})
		case age >= establishedAge:
			a.add(wEstablished, Signal{Code: "ESTABLISHED_PACKAGE", Severity: SigLow,
				Message: "Public package is well established",
				Detail:  fmt.Sprintf("%dd old", days)})
		}
	}

	// --- timing: did it appear after we started watching the name? ---------------
	// If the public package was created after our first observation of the internal
	// one, it cannot be a pre-existing coincidence. This is the strongest available
	// timing signal without knowing the internal package's own creation date.
	if prev != nil && !p.CreatedAt.IsZero() && !prev.FirstSeen.IsZero() &&
		p.CreatedAt.After(prev.FirstSeen) {
		a.add(wPublishedAfterMonitoring, Signal{Code: "PUBLISHED_AFTER_MONITORING", Severity: SigHigh,
			Message: "Public package appeared after depwatch began tracking this name",
			Detail:  p.CreatedAt.Format("2006-01-02")})
	}

	// --- attribution: can this package be traced to anyone? ----------------------
	if p.Publisher == "" {
		a.add(wNoPublisher, Signal{Code: "UNVERIFIED_PUBLISHER", Severity: SigMed,
			Message: "Public package has no associated publisher identity"})
	} else {
		a.add(wHasPublisher, Signal{Code: "NAMED_PUBLISHER", Severity: SigLow,
			Message: "Public package has a named publisher", Detail: p.Publisher})
	}
	if p.Repository == "" {
		a.add(wNoRepository, Signal{Code: "NO_SOURCE_REPOSITORY", Severity: SigMed,
			Message: "Public package publishes no source repository"})
	} else {
		a.add(wHasRepo, Signal{Code: "SOURCE_PUBLISHED", Severity: SigLow,
			Message: "Public package publishes a source repository"})
	}

	// --- adoption: only judged when the registry actually reports counts ---------
	// Several registries (PyPI, crates.io metadata) do not return download totals.
	// Treating an absent count as "zero installs" would manufacture suspicion, so
	// download rules apply only when a positive count is known.
	if p.Downloads > 0 {
		switch {
		case p.Downloads >= hugeDownloads:
			a.add(wVeryPopular, Signal{Code: "WIDELY_USED", Severity: SigLow,
				Message: "Public package is widely installed", Detail: downloads(p.Downloads)})
		case p.Downloads >= popularDownloads:
			a.add(wPopular, Signal{Code: "ESTABLISHED_USAGE", Severity: SigLow,
				Message: "Public package has substantial install history", Detail: downloads(p.Downloads)})
		case p.Downloads < fewDownloads:
			a.add(wFewDownloads, Signal{Code: "LOW_REPUTATION", Severity: SigLow,
				Message: "Public package has very low download history", Detail: downloads(p.Downloads)})
		}
	} else if knownZeroDownloads(p) {
		a.add(wNoDownloads, Signal{Code: "NO_DOWNLOADS", Severity: SigMed,
			Message: "Public package reports no installs at all"})
	}

	// --- history: a previously benign collision that got worse deserves a nudge --
	if prev != nil && prev.Risk != "" {
		if RiskOrder[riskFromThreat(classify(a.Score), c.Type)] > RiskOrder[prev.Risk] {
			a.add(wRiskEscalated, Signal{Code: "RISK_ESCALATED", Severity: SigMed,
				Message: "Assessment worsened since the previous observation",
				Detail:  "was " + string(prev.Risk)})
		}
	}

	a.Threat = classify(a.Score)
	a.Risk = riskFromThreat(a.Threat, c.Type)
	return a
}

// add records a signal and its contribution to the threat score.
func (a *Assessment) add(weight int, s Signal) {
	a.Signals = append(a.Signals, s)
	a.Score += weight
}

// knownZeroDownloads reports whether the registry genuinely told us the package has
// no installs, as opposed to not reporting the metric at all. npm always returns a
// count, so a zero there is meaningful.
func knownZeroDownloads(p PackageInfo) bool {
	return p.Registry == RegistryNpm
}

// downloads renders a count compactly for signal detail text.
func downloads(n int64) string {
	switch {
	case n >= 1000000:
		return fmt.Sprintf("%.1fM downloads", float64(n)/1000000)
	case n >= 1000:
		return fmt.Sprintf("%.0fk downloads", float64(n)/1000)
	default:
		return fmt.Sprintf("%d downloads", n)
	}
}

// RiskAtLeast reports whether r is at least as severe as min.
func RiskAtLeast(r, min RiskLevel) bool {
	return RiskOrder[r] >= RiskOrder[min]
}
