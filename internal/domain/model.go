// Package domain holds the core types and pure logic of depwatch. It has no
// dependency on any other internal package and performs no I/O. Keeping it pure
// means the security decisions (collision detection, signal analysis) live in one
// auditable, trivially testable place, and infrastructure (HTTP, SQLite, Slack)
// is pushed to the edges.
//
// The dependency graph is: everything → domain. Nothing → domain. This is the
// architectural invariant that keeps the security logic trustworthy.
package domain

import "time"

// RegistryName identifies a public package registry. Each adapter in the
// registry package maps one RegistryName to its HTTP API. The string values
// match the YAML config keys and the user-facing output.
type RegistryName string

const (
	RegistryNpm    RegistryName = "npm"
	RegistryPypi   RegistryName = "pypi"
	RegistryCrates RegistryName = "crates"
)

// Ecosystem groups packages by their package manager / registry family. In the
// MVP an ecosystem maps 1:1 to a RegistryName, but the distinction is kept so V2
// can support multiple registries per ecosystem (e.g. GitHub Packages, private
// mirrors). The config uses ecosystem names as keys; the scanner pairs each
// internal package with its ecosystem's matching registry.
type Ecosystem string

const (
	EcosystemNpm    Ecosystem = "npm"
	EcosystemPypi   Ecosystem = "pypi"
	EcosystemCrates Ecosystem = "crates"
)

// PackageInfo is the normalized representation of a package as returned by any
// registry adapter. Adapters translate their registry's proprietary JSON into
// this struct so that every consumer downstream (detection, analysis, storage,
// output) speaks one language. This is the anti-leakage boundary: registry quirks
// never escape the adapter that produced them.
//
// Not all fields are populated by every registry:
//   - Downloads: npm returns a count; PyPI/crates omit it (stays 0)
//   - Repository: PyPI may return "UNKNOWN" which is normalized to "" by clean()
//   - Publisher: npm uses maintainer name; PyPI uses author/maintainer
//   - CreatedAt: derived from earliest upload (PyPI) or creation timestamp (npm/crates)
type PackageInfo struct {
	Name       string
	Registry   RegistryName
	Version    string
	Publisher  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Downloads  int64
	Repository string
	Homepage   string
	TarballURL string
	Integrity  string
}

// InternalPackage is one entry from the organization's inventory: a package name
// that is expected to resolve from a trusted internal registry, not a public one.
// The scanner checks whether a public package with the same name exists — if it
// does, that's a dependency confusion collision.
type InternalPackage struct {
	Name      string
	Ecosystem Ecosystem
	// InternalRegistry is the URL of the private registry that should serve this
	// package. Reserved for V2 resolution-conflict analysis; optional in MVP.
	InternalRegistry string
}

// CollisionType distinguishes how an internal package relates to a public one.
// This distinction drives the risk assessment: an exact name match is inherently
// more dangerous than a namespace collision.
type CollisionType string

const (
	CollisionExact     CollisionType = "EXACT"     // byte-identical names
	CollisionNamespace CollisionType = "NAMESPACE" // same scope, different leaf
)

// Collision records that a public package collides with an internal one. It is the
// central finding from which every downstream artifact (signals, alert, output)
// is derived. The struct carries both sides of the collision so downstream code
// can access metadata from either the internal or public package.
type Collision struct {
	Internal InternalPackage
	Public   PackageInfo
	Type     CollisionType
}

// SignalSeverity classifies the weight of a single security signal within the
// assessment. HIGH signals are strong indicators of squat behavior; LOW signals
// provide context that shifts the verdict in either direction.
type SignalSeverity string

const (
	SigHigh SignalSeverity = "HIGH"
	SigMed  SignalSeverity = "MED"
	SigLow  SignalSeverity = "LOW"
)

// Signal is an explainable security finding. Unlike an opaque numeric score, a
// signal tells the analyst exactly what triggered the flag and at what severity,
// satisfying the project's "explanation second" principle. Every signal has a
// machine-readable Code (for programmatic filtering) and a human-readable Message
// (for terminal output). Detail provides a concrete fact backing the signal
// ("4307d old", "1.2M downloads").
type Signal struct {
	Code     string
	Severity SignalSeverity
	Message  string
	Detail   string
}

// RiskLevel is the aggregate severity used for sorting and alerting. It is always
// derivable from the signals that produced it (see analyze.go). The ordering is
// total: RiskOrder provides integer comparisons for threshold checks.
type RiskLevel string

const (
	RiskInfo     RiskLevel = "INFO"     // no collision detected
	RiskLow      RiskLevel = "LOW"      // collision but clearly benign
	RiskMedium   RiskLevel = "MEDIUM"   // some indicators warrant a look
	RiskHigh     RiskLevel = "HIGH"     // likely threat, investigate
	RiskCritical RiskLevel = "CRITICAL" // multiple squat indicators, investigate now
)

// RiskOrder gives a total ordering over risk levels for threshold comparisons.
// Used by config validation, alerting thresholds, and the CI gate.
var RiskOrder = map[RiskLevel]int{
	RiskInfo:     0,
	RiskLow:      1,
	RiskMedium:   2,
	RiskHigh:     3,
	RiskCritical: 4,
}

// ScanStatus records whether a scan observed a collision and what changed since
// the last observation. The status drives the terminal icons (✓/⚠/•/✗) and the
// alert classification (NEW_COLLISION vs RISK_ESCALATION).
type ScanStatus string

const (
	StatusSafe    ScanStatus = "SAFE"    // no public package exists
	StatusNew     ScanStatus = "NEW"     // collision observed for the first time
	StatusKnown   ScanStatus = "KNOWN"   // seen before, risk unchanged
	StatusChanged ScanStatus = "CHANGED" // seen before, risk escalated
)

// ScanEntry is one persisted result for a single (package, registry) pair. It
// carries everything needed for terminal rendering, history display, and alert
// generation. The Collision field is nil for safe lookups (no public match found).
//
// Threat is derived deterministically from Signals on every scan, so it needs no
// storage column — it is recomputed from the stored signals when rendering history.
type ScanEntry struct {
	PackageName string
	Ecosystem   Ecosystem
	Registry    RegistryName
	Collision   *Collision // nil when StatusSafe
	Signals     []Signal
	Risk        RiskLevel
	Threat      ThreatLevel
	Status      ScanStatus
	FirstSeen   time.Time
	LastSeen    time.Time
	Version     string
	Publisher   string
	Downloads   int64
}

// ScanResult aggregates all entries from one scan run. It is the top-level
// return type for Scan, Package, and CI operations. Partial is true when one or
// more registries were unavailable — callers must not treat missing entries as
// "safe" when Partial is true.
type ScanResult struct {
	StartedAt time.Time
	Entries   []ScanEntry
	Partial   bool
	Errors    []string // human-readable registry failure messages
}

// AlertType enumerates the meaningful events that warrant a notification.
type AlertType string

const (
	AlertNewCollision   AlertType = "NEW_COLLISION"
	AlertRiskEscalation AlertType = "RISK_ESCALATION"
	AlertNewVersion     AlertType = "NEW_VERSION"
)

// Alert is a notification-worthy event derived from a ScanEntry. Alerts are
// persisted before delivery so they survive Slack failures and can be listed
// with `depwatch alerts`. The Signals field carries the full evidence context
// for the Slack message.
type Alert struct {
	PackageName string
	Registry    RegistryName
	Risk        RiskLevel
	Type        AlertType
	CreatedAt   time.Time
	Signals     []Signal
}
