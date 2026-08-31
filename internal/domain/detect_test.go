package domain

import (
	"testing"
	"time"
)

func TestDetectCollision_Exact(t *testing.T) {
	internal := InternalPackage{Name: "acme-auth", Ecosystem: EcosystemPypi}
	pub := &PackageInfo{Name: "acme-auth", Registry: RegistryPypi}

	c, ok := DetectCollision(internal, pub)
	if !ok {
		t.Fatal("expected collision")
	}
	if c.Type != CollisionExact {
		t.Fatalf("got %s, want EXACT", c.Type)
	}
}

func TestDetectCollision_Namespace(t *testing.T) {
	internal := InternalPackage{Name: "@acme/auth", Ecosystem: EcosystemNpm}
	pub := &PackageInfo{Name: "@acme/utils", Registry: RegistryNpm}

	c, ok := DetectCollision(internal, pub)
	if !ok {
		t.Fatal("expected namespace collision")
	}
	if c.Type != CollisionNamespace {
		t.Fatalf("got %s, want NAMESPACE", c.Type)
	}
}

func TestDetectCollision_NoMatch(t *testing.T) {
	internal := InternalPackage{Name: "acme-auth", Ecosystem: EcosystemPypi}
	pub := &PackageInfo{Name: "acme-other", Registry: RegistryPypi}

	if _, ok := DetectCollision(internal, pub); ok {
		t.Fatal("did not expect collision")
	}
}

func TestDetectCollision_NilPublic(t *testing.T) {
	internal := InternalPackage{Name: "acme-auth"}
	if _, ok := DetectCollision(internal, nil); ok {
		t.Fatal("nil public must never collide")
	}
}

func TestDetectCollision_ScopedVsUnscoped(t *testing.T) {
	// An unscoped internal must not namespace-collide with a scoped public.
	internal := InternalPackage{Name: "acme-auth"}
	pub := &PackageInfo{Name: "@acme/auth"}
	if _, ok := DetectCollision(internal, pub); ok {
		t.Fatal("unscoped must not namespace-collide with scoped")
	}
}

func TestSplitScope(t *testing.T) {
	cases := []struct {
		in    string
		scope string
		local string
	}{
		{"@acme/auth", "@acme/", "auth"},
		{"@scope/x/y", "@scope/", "x/y"},
		{"acme-auth", "", "acme-auth"},
		{"@lonely", "", "@lonely"},
	}
	for _, c := range cases {
		scope, local := splitScope(c.in)
		if scope != c.scope || local != c.local {
			t.Fatalf("splitScope(%q) = (%q,%q), want (%q,%q)", c.in, scope, local, c.scope, c.local)
		}
	}
}

func TestAnalyze_ExactFreshCritical(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pub := PackageInfo{
		Name:       "acme-auth",
		CreatedAt:  now.Add(-2 * 24 * time.Hour), // recent
		Publisher:  "",                           // unverified
		Repository: "",                           // no repo
		Downloads:  10,
	}
	c := &Collision{Type: CollisionExact, Public: pub}

	got := Analyze(c, nil, now, "acme")
	if got.Risk != RiskCritical {
		t.Fatalf("got %s, want CRITICAL", got.Risk)
	}
	if got.Threat != ThreatDangerous {
		t.Fatalf("got threat %s, want DANGEROUS", got.Threat)
	}
}

func TestAnalyze_ExactEstablishedInfo(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pub := PackageInfo{
		Name:       "acme-auth",
		CreatedAt:  now.Add(-10 * 365 * 24 * time.Hour), // old
		Publisher:  "acme-inc",
		Repository: "https://github.com/acme/auth",
		Downloads:  100000,
	}
	c := &Collision{Type: CollisionExact, Public: pub}

	got := Analyze(c, nil, now, "acme")
	if got.Risk != RiskInfo {
		t.Fatalf("got %s, want INFO", got.Risk)
	}
}

func TestAnalyze_NamespaceLow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pub := PackageInfo{
		Name:       "@acme/utils",
		CreatedAt:  now.Add(-5 * 365 * 24 * time.Hour),
		Publisher:  "acme-inc",
		Repository: "https://github.com/acme/utils",
		Downloads:  50000,
	}
	c := &Collision{Type: CollisionNamespace, Public: pub}

	got := Analyze(c, nil, now, "acme")
	if got.Risk != RiskLow {
		t.Fatalf("got %s, want LOW", got.Risk)
	}
}

func TestRiskAtLeast(t *testing.T) {
	if !RiskAtLeast(RiskHigh, RiskMedium) {
		t.Fatal("HIGH should be >= MEDIUM")
	}
	if RiskAtLeast(RiskLow, RiskCritical) {
		t.Fatal("LOW should not be >= CRITICAL")
	}
}
