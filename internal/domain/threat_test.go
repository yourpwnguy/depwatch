package domain

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func days(n int) time.Time { return testNow.Add(-time.Duration(n) * 24 * time.Hour) }

// legit models a long-established, attributable, widely-used public package.
func legit(name string) PackageInfo {
	return PackageInfo{
		Name: name, Registry: RegistryNpm, Version: "1.4.1",
		CreatedAt: days(4307), Publisher: "Christopher Simpkins",
		Repository: "https://github.com/chrissimpkins/crypto", Downloads: 5000000,
	}
}

// squat models a freshly published, unattributable package with no installs.
func squat(name string) PackageInfo {
	return PackageInfo{
		Name: name, Registry: RegistryNpm, Version: "0.0.1",
		CreatedAt: days(3), Downloads: 0,
	}
}

// TestThreat_LegitimateEstablishedPackage is the headline requirement: a generic name
// like "crypto" existing publicly is a real collision, but an old, popular, sourced
// package must not be reported as a high risk just because the name matches.
func TestThreat_LegitimateEstablishedPackage(t *testing.T) {
	c := &Collision{
		Type:     CollisionExact,
		Internal: InternalPackage{Name: "crypto", Ecosystem: EcosystemNpm},
		Public:   legit("crypto"),
	}
	got := Analyze(c, nil, testNow, "acme")

	if got.Threat != ThreatBenign {
		t.Fatalf("threat = %s (score %d), want BENIGN\n%s", got.Threat, got.Score, dump(got))
	}
	if got.Risk != RiskInfo {
		t.Fatalf("risk = %s, want INFO", got.Risk)
	}
	if !hasSignal(got, "EXACT_NAME_COLLISION") {
		t.Fatal("collision must still be reported even when benign")
	}
	// The verdict has to be explainable by mitigating evidence, not just a low score.
	for _, code := range []string{"LONG_ESTABLISHED", "WIDELY_USED", "SOURCE_PUBLISHED", "NAMED_PUBLISHER"} {
		if !hasSignal(got, code) {
			t.Errorf("missing mitigating signal %s\n%s", code, dump(got))
		}
	}
}

// TestThreat_NewSuspiciousPackage covers the attack shape: an org-specific name that
// suddenly appears publicly, brand new, with no publisher, repo, or installs.
func TestThreat_NewSuspiciousPackage(t *testing.T) {
	c := &Collision{
		Type:     CollisionExact,
		Internal: InternalPackage{Name: "acme-billing", Ecosystem: EcosystemNpm},
		Public:   squat("acme-billing"),
	}
	got := Analyze(c, nil, testNow, "acme")

	if got.Threat != ThreatDangerous {
		t.Fatalf("threat = %s (score %d), want DANGEROUS\n%s", got.Threat, got.Score, dump(got))
	}
	if got.Risk != RiskCritical {
		t.Fatalf("risk = %s, want CRITICAL", got.Risk)
	}
	for _, code := range []string{"NEWLY_REGISTERED", "UNVERIFIED_PUBLISHER", "NO_SOURCE_REPOSITORY", "ORG_SPECIFIC_NAME"} {
		if !hasSignal(got, code) {
			t.Errorf("missing aggravating signal %s\n%s", code, dump(got))
		}
	}
}

// TestThreat_GenericNameLowersConfidence checks that an identical public package is
// judged less harshly under a generic name than under an org-shaped one.
func TestThreat_GenericNameLowersConfidence(t *testing.T) {
	pub := squat("utils")
	generic := Analyze(&Collision{
		Type:     CollisionExact,
		Internal: InternalPackage{Name: "utils"},
		Public:   pub,
	}, nil, testNow, "acme")

	orgShaped := Analyze(&Collision{
		Type:     CollisionExact,
		Internal: InternalPackage{Name: "acme-utils"},
		Public:   pub,
	}, nil, testNow, "acme")

	if generic.Score >= orgShaped.Score {
		t.Fatalf("generic score %d should be below org-specific score %d",
			generic.Score, orgShaped.Score)
	}
	if !hasSignal(generic, "GENERIC_NAME") {
		t.Errorf("generic name signal missing\n%s", dump(generic))
	}
	if ThreatOrder[generic.Threat] > ThreatOrder[orgShaped.Threat] {
		t.Errorf("generic %s must not outrank org-specific %s", generic.Threat, orgShaped.Threat)
	}
}

// TestThreat_OrgSpecificCollisionIsEscalated ensures an org-shaped name is escalated
// even when the public package looks otherwise unremarkable.
func TestThreat_OrgSpecificCollisionIsEscalated(t *testing.T) {
	// Deliberately unremarkable: mid-age, attributable, modest audience. Age is a
	// legitimate mitigator, so this is tested without the decade-old head start —
	// a genuinely ancient package sharing an org name is far more likely coincidence.
	pub := PackageInfo{
		Name: "@acme/scheduler", Registry: RegistryNpm, Version: "1.2.0",
		CreatedAt: days(200), Publisher: "someone",
		Repository: "https://github.com/someone/scheduler", Downloads: 200,
	}
	got := Analyze(&Collision{
		Type:     CollisionExact,
		Internal: InternalPackage{Name: "@acme/scheduler"},
		Public:   pub,
	}, nil, testNow, "acme")

	if !hasSignal(got, "ORG_SPECIFIC_NAME") {
		t.Fatalf("org-specific signal missing\n%s", dump(got))
	}
	if got.Threat == ThreatBenign {
		t.Fatalf("org-specific collision should not be benign\n%s", dump(got))
	}
}

// TestThreat_PublishedAfterMonitoring covers the historical dimension: a name we have
// been watching that only now exists publicly cannot be a pre-existing coincidence.
func TestThreat_PublishedAfterMonitoring(t *testing.T) {
	prev := &ScanEntry{
		PackageName: "acme-internal-sdk",
		Risk:        RiskInfo,
		FirstSeen:   days(400),
	}
	pub := squat("acme-internal-sdk")
	pub.CreatedAt = days(10) // published long after we started watching

	got := Analyze(&Collision{
		Type:     CollisionExact,
		Internal: InternalPackage{Name: "acme-internal-sdk"},
		Public:   pub,
	}, prev, testNow, "acme")

	if !hasSignal(got, "PUBLISHED_AFTER_MONITORING") {
		t.Fatalf("timing signal missing\n%s", dump(got))
	}
	if got.Threat != ThreatDangerous {
		t.Fatalf("threat = %s, want DANGEROUS\n%s", got.Threat, dump(got))
	}
}

// TestThreat_EstablishedPackageStaysBenignAcrossRescan pins the KNOWN path: re-scanning
// an unchanged, legitimate package must not drift into a higher threat.
func TestThreat_EstablishedPackageStaysBenignAcrossRescan(t *testing.T) {
	c := &Collision{
		Type:     CollisionExact,
		Internal: InternalPackage{Name: "crypto"},
		Public:   legit("crypto"),
	}
	first := Analyze(c, nil, testNow, "acme")
	prev := &ScanEntry{PackageName: "crypto", Risk: first.Risk, FirstSeen: days(30)}
	second := Analyze(c, prev, testNow, "acme")

	if second.Threat != first.Threat || second.Risk != first.Risk {
		t.Fatalf("re-scan drifted: %s/%s -> %s/%s",
			first.Threat, first.Risk, second.Threat, second.Risk)
	}
	if hasSignal(second, "RISK_ESCALATED") {
		t.Errorf("unchanged package must not report escalation\n%s", dump(second))
	}
}

// TestThreat_RiskEscalationIsReported covers a previously benign collision that has
// since become dangerous, which is what the NEW/KNOWN history exists to surface.
func TestThreat_RiskEscalationIsReported(t *testing.T) {
	prev := &ScanEntry{PackageName: "acme-billing", Risk: RiskInfo, FirstSeen: days(500)}
	got := Analyze(&Collision{
		Type:     CollisionExact,
		Internal: InternalPackage{Name: "acme-billing"},
		Public:   squat("acme-billing"),
	}, prev, testNow, "acme")

	if !hasSignal(got, "RISK_ESCALATED") {
		t.Fatalf("escalation signal missing\n%s", dump(got))
	}
}

// TestThreat_MissingDownloadCountIsNotSuspicion guards a real false-positive source:
// PyPI does not report download totals, and an absent metric must never be read as
// "zero installs".
func TestThreat_MissingDownloadCountIsNotSuspicion(t *testing.T) {
	pub := legit("requests")
	pub.Registry = RegistryPypi
	pub.Downloads = 0

	got := Analyze(&Collision{
		Type:     CollisionExact,
		Internal: InternalPackage{Name: "requests"},
		Public:   pub,
	}, nil, testNow, "acme")

	if hasSignal(got, "NO_DOWNLOADS") || hasSignal(got, "LOW_REPUTATION") {
		t.Fatalf("absent download metric must not create suspicion\n%s", dump(got))
	}
	if got.Threat != ThreatBenign {
		t.Fatalf("threat = %s, want BENIGN\n%s", got.Threat, dump(got))
	}
}

func TestIsGenericName(t *testing.T) {
	for _, n := range []string{"crypto", "utils", "logger", "@acme/utils", "Crypto"} {
		if !IsGenericName(n) {
			t.Errorf("%q should be generic", n)
		}
	}
	for _, n := range []string{"acme-billing", "acme_crypto", "@acme/scheduler"} {
		if IsGenericName(n) {
			t.Errorf("%q should not be generic", n)
		}
	}
}

func TestIsOrgSpecificName(t *testing.T) {
	for _, n := range []string{"@acme/scheduler", "acme-billing", "acme_crypto", "billing.acme.core"} {
		if !IsOrgSpecificName(n, "acme") {
			t.Errorf("%q should be org-specific", n)
		}
	}
	for _, n := range []string{"crypto", "requests", "acmecorp-billing"} {
		if IsOrgSpecificName(n, "acme") {
			t.Errorf("%q should not be org-specific", n)
		}
	}
	if IsOrgSpecificName("acme-billing", "") {
		t.Error("empty org must never match")
	}
}

func hasSignal(a Assessment, code string) bool {
	for _, s := range a.Signals {
		if s.Code == code {
			return true
		}
	}
	return false
}

func dump(a Assessment) string {
	out := "  threat=" + string(a.Threat) + " risk=" + string(a.Risk) + " signals:\n"
	for _, s := range a.Signals {
		out += "    " + string(s.Severity) + " " + s.Code + " " + s.Detail + "\n"
	}
	return out
}
