package domain

import (
	"slices"
	"strings"
	"time"
)

// ThreatLevel is the judgement of whether a collision is an actual dependency
// confusion threat, as opposed to a harmless name clash.
//
// This is deliberately separate from RiskLevel. RiskLevel answers "how severe is a
// collision of this shape" and drives the existing alert/CI thresholds. ThreatLevel
// answers the question an analyst actually asks: is this public package plausibly an
// attacker's squat, or is it a legitimate, long-established project that happens to
// share a name? A package like `crypto` on PyPI is a real collision but not a threat.
type ThreatLevel string

const (
	ThreatBenign     ThreatLevel = "BENIGN"     // established, attributable, widely used
	ThreatSuspicious ThreatLevel = "SUSPICIOUS" // some indicators warrant a look
	ThreatDangerous  ThreatLevel = "DANGEROUS"  // multiple squat indicators; investigate now
)

// ThreatOrder gives a total ordering for comparisons and sorting.
var ThreatOrder = map[ThreatLevel]int{ThreatBenign: 0, ThreatSuspicious: 1, ThreatDangerous: 2}

// Assessment is the full explainable outcome of analyzing one collision: the signals
// that fired (both aggravating and mitigating), the aggregate risk kept for existing
// thresholds, the threat judgement, and the raw score so the decision is auditable.
type Assessment struct {
	Signals []Signal
	Risk    RiskLevel
	Threat  ThreatLevel
	Score   int
}

// Scoring weights. Positive values argue "this looks like a squat", negative values
// argue "this looks like a legitimate package". They are small integers rather than
// tuned floats so that any classification can be re-derived by hand from the printed
// signals — the tool must never produce a verdict it cannot explain.
const (
	wPublishedAfterMonitoring = 4 // appeared while we were already watching the name
	wBrandNew                 = 4 // < 30 days old
	wRecent                   = 3 // < 90 days old
	wYoung                    = 1 // < 1 year old
	wNoRepository             = 2
	wNoPublisher              = 2
	wNoDownloads              = 3 // known-zero installs
	wFewDownloads             = 2
	wOrgSpecificName          = 3 // an org-shaped private name has no reason to exist publicly
	wRiskEscalated            = 1

	wEstablished  = -3 // >= 2 years old
	wVeryOld      = -4 // >= 5 years old
	wPopular      = -2 // >= 10k downloads
	wVeryPopular  = -4 // >= 1M downloads
	wHasRepo      = -2
	wHasPublisher = -1
	wGenericName  = -3 // a dictionary word collides by coincidence, not by targeting
)

// Threat thresholds over the accumulated score.
const (
	dangerousAt  = 6
	suspiciousAt = 1
)

// Age and popularity boundaries, named so the rules read like the policy they encode.
const (
	brandNewAge    = 30 * 24 * time.Hour
	recentAge      = 90 * 24 * time.Hour
	youngAge       = 365 * 24 * time.Hour
	establishedAge = 2 * 365 * 24 * time.Hour
	veryOldAge     = 5 * 365 * 24 * time.Hour

	fewDownloads     = 1000
	popularDownloads = 10000
	hugeDownloads    = 1000000
)

// genericNames are names common enough that a public package owning one is almost
// certainly unrelated to any given company's internal package of the same name. A
// collision on these carries far less signal than a collision on an org-shaped name.
var genericNames = map[string]bool{
	"api": true, "auth": true, "base": true, "cache": true, "client": true,
	"common": true, "config": true, "core": true, "crypto": true, "data": true,
	"email": true, "event": true, "events": true, "helper": true, "helpers": true,
	"http": true, "image": true, "json": true, "lib": true, "logger": true,
	"logging": true, "math": true, "message": true, "models": true, "parser": true,
	"proxy": true, "queue": true, "router": true, "schema": true, "sdk": true,
	"secret": true, "security": true, "server": true, "session": true, "storage": true,
	"stream": true, "string": true, "task": true, "template": true, "test": true,
	"tests": true, "time": true, "token": true, "tools": true, "utils": true,
	"util": true, "uuid": true, "validator": true, "worker": true,
}

// IsGenericName reports whether a package name is a common dictionary-style term.
// Scope is stripped first so "@acme/utils" is judged on its leaf name.
func IsGenericName(name string) bool {
	leaf := name
	if i := strings.LastIndex(leaf, "/"); i >= 0 {
		leaf = leaf[i+1:]
	}
	return genericNames[strings.ToLower(strings.TrimSpace(leaf))]
}

// IsOrgSpecificName reports whether a name is shaped like private, org-owned code:
// either it is scoped to the organization (@acme/...) or the org token appears as a
// segment of the name (acme-billing, acme_crypto). Such a name existing publicly is
// far more likely to be deliberate targeting than coincidence.
func IsOrgSpecificName(name, org string) bool {
	org = strings.ToLower(strings.TrimSpace(org))
	if org == "" {
		return false
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(name, "@"+org+"/") {
		return true
	}
	return slices.Contains(strings.FieldsFunc(name, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == '/' || r == '@'
	}), org)
}

// classify converts an accumulated score into a threat level. Kept as one small
// function so the only place a verdict is decided is obvious in review.
func classify(score int) ThreatLevel {
	switch {
	case score >= dangerousAt:
		return ThreatDangerous
	case score >= suspiciousAt:
		return ThreatSuspicious
	default:
		return ThreatBenign
	}
}

// riskFromThreat maps the threat judgement onto the existing RiskLevel scale, which
// alerting and the CI gate already consume. An exact-name collision is inherently
// worse than a namespace one at the same threat level. This is what stops an old,
// established, well-attributed package from being reported as HIGH purely because
// its name matches.
func riskFromThreat(t ThreatLevel, c CollisionType) RiskLevel {
	exact := c == CollisionExact
	switch t {
	case ThreatDangerous:
		if exact {
			return RiskCritical
		}
		return RiskHigh
	case ThreatSuspicious:
		if exact {
			return RiskHigh
		}
		return RiskMedium
	default:
		if exact {
			return RiskInfo
		}
		return RiskLow
	}
}
