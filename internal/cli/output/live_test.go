package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// TestLiveScan_Renders drives the renderer through a full scan lifecycle (queued ->
// querying -> done) and checks the key elements appear: the cat banner, a SAFE line,
// a COLLISION line with its risk, and the completed summary. It uses a bytes.Buffer
// so it runs without a terminal.
func TestLiveScan_Renders(t *testing.T) {
	var buf bytes.Buffer
	items := []LiveItem{
		{Pkg: "react", Reg: "npm"},
		{Pkg: "acme_crypto", Reg: "crates"},
	}
	stats := LiveStats{Org: "acme", Registries: "npm · crates", Inventory: 2, Workers: 8, Store: "depwatch.db"}
	lr := NewLiveScan(&buf, stats, items)

	lr.Start()

	lr.Event(domain.ProgressEvent{Package: "react", Registry: "npm", Phase: domain.PhaseQuerying})
	lr.Tick()
	lr.Event(domain.ProgressEvent{Package: "react", Registry: "npm", Phase: domain.PhaseDone, Status: domain.StatusSafe, Risk: domain.RiskInfo})
	lr.Event(domain.ProgressEvent{Package: "acme_crypto", Registry: "crates", Phase: domain.PhaseQuerying})
	lr.Event(domain.ProgressEvent{Package: "acme_crypto", Registry: "crates", Phase: domain.PhaseAnalyzing})
	lr.Event(domain.ProgressEvent{Package: "acme_crypto", Registry: "crates", Phase: domain.PhaseDone,
		Status: domain.StatusNew, Risk: domain.RiskCritical,
		Signals: []domain.Signal{{Message: "exact name match"}}})
	lr.Finish()

	out := buf.String()
	checks := map[string]string{
		"cat banner":        "depwatch",
		"org stat":          "acme",
		"SAFE icon":         "✓",
		"safe package":      "react",
		"collision icon":    "⚠",
		"collision package": "acme_crypto",
		"risk label":        "CRITICAL",
		"signal text":       "exact name match",
		"verdict":           "doki",
		"tally":             "2 packages · 1 collisions · 1 critical",
	}
	for name, want := range checks {
		if !strings.Contains(out, want) {
			t.Fatalf("renderer missing %s (%q) in output:\n%s", name, want, out)
		}
	}
}

// TestLiveScan_ScopedPackage guards a real regression: scoped npm names start with
// '@', so deriving the package/registry by splitting the "pkg@reg" state key produced
// an empty PACKAGE column and pushed the whole key into REGISTRY. The row must place
// the scoped name and the registry in their own columns.
func TestLiveScan_ScopedPackage(t *testing.T) {
	var buf bytes.Buffer
	items := []LiveItem{{Pkg: "@acme/scheduler", Reg: "npm"}}
	lr := NewLiveScan(&buf, LiveStats{Org: "acme", Inventory: 1, Workers: 8}, items)
	lr.Event(domain.ProgressEvent{
		Package: "@acme/scheduler", Registry: "npm", Phase: domain.PhaseDone,
		Status: domain.StatusSafe, Risk: domain.RiskInfo,
	})
	lr.Finish()

	out := buf.String()
	if !strings.Contains(out, "@acme/scheduler") {
		t.Fatalf("scoped package name missing:\n%s", out)
	}
	// The broken rendering collapsed name+registry into one token.
	if strings.Contains(out, "@acme/scheduler@npm") {
		t.Fatalf("scoped name and registry were not split into columns:\n%s", out)
	}
	// The registry must still appear as its own column value.
	if !strings.Contains(out, "npm") {
		t.Fatalf("registry column missing:\n%s", out)
	}
}
