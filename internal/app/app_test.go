package app_test

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yourpwnguy/depwatch/internal/app"
	"github.com/yourpwnguy/depwatch/internal/config"
	"github.com/yourpwnguy/depwatch/internal/domain"
	"github.com/yourpwnguy/depwatch/internal/registry"
	"github.com/yourpwnguy/depwatch/internal/storage"
)

// fakeRegistry is an in-memory Registry used to exercise the scan pipeline without
// touching the network. It returns a colliding public package for names it knows.
type fakeRegistry struct {
	name    domain.RegistryName
	collide map[string]*domain.PackageInfo
}

func (f *fakeRegistry) Name() domain.RegistryName { return f.name }

func (f *fakeRegistry) Query(ctx context.Context, name string) (*domain.PackageInfo, error) {
	if p, ok := f.collide[name]; ok {
		return p, nil
	}
	return nil, nil // not found -> safe
}

func newTestApp(t *testing.T, regs ...registry.Registry) (*app.App, *storage.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app_test.db")
	store, err := storage.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	cfg := &config.Config{
		Organization: "test",
		Ecosystems:   map[string][]string{"npm": {"evil-dep", "safe-dep"}},
		Registries:   map[string]*config.RegistryConfig{"npm": {Enabled: true}},
	}
	cfg.ApplyDefaults()
	return app.New(cfg, regs, store), store
}

func TestApp_ScanDetectsCollisionAndAlerts(t *testing.T) {
	now := time.Now()
	fake := &fakeRegistry{
		name: domain.RegistryNpm,
		collide: map[string]*domain.PackageInfo{
			// exact match with an internal package + newly registered + no publisher
			"evil-dep": {
				Name:      "evil-dep",
				Registry:  domain.RegistryNpm,
				Version:   "1.0.0",
				CreatedAt: now, // within 90d -> NEWLY_REGISTERED
				// Publisher and Repository left empty -> suspicion signals
			},
		},
	}

	a, store := newTestApp(t, fake)
	res, err := a.Scan(context.Background(), app.ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Partial {
		t.Fatalf("unexpected partial scan: %v", res.Errors)
	}

	// Two packages (evil-dep, safe-dep); evil-dep must be a CRITICAL collision.
	var found bool
	for _, e := range res.Entries {
		if e.PackageName == "evil-dep" {
			found = true
			if e.Status == domain.StatusSafe {
				t.Fatalf("evil-dep should not be safe: %+v", e)
			}
			if e.Risk != domain.RiskCritical {
				t.Fatalf("evil-dep expected CRITICAL, got %s", e.Risk)
			}
		}
	}
	if !found {
		t.Fatal("evil-dep missing from results")
	}

	// The collision must have been persisted and raised as an alert.
	alerts, err := store.UnresolvedAlerts()
	if err != nil {
		t.Fatalf("alerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for the critical collision, got %d", len(alerts))
	}

	latest, err := store.Latest("evil-dep", string(domain.RegistryNpm))
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest == nil || latest.Risk != domain.RiskCritical {
		t.Fatalf("expected persisted critical entry, got %+v", latest)
	}
}

// TestApp_ScanOnlyAlertsOnNewOrChanged pins the alert-dedupe fix: a collision
// alerts once when it is first discovered (NEW), and a rescan that finds the
// same risk (KNOWN) must not add another alert. Otherwise every scan cycle
// spams the channel and the alerts table grows forever.
func TestApp_ScanOnlyAlertsOnNewOrChanged(t *testing.T) {
	fake := &fakeRegistry{
		name: domain.RegistryNpm,
		collide: map[string]*domain.PackageInfo{
			"evil-dep": {
				Name:      "evil-dep",
				Registry:  domain.RegistryNpm,
				Version:   "1.0.0",
				CreatedAt: time.Now(),
			},
		},
	}
	a, store := newTestApp(t, fake)

	if _, err := a.Scan(context.Background(), app.ScanOptions{}); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	alerts, err := store.UnresolvedAlerts()
	if err != nil {
		t.Fatalf("alerts after first scan: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("first scan should add 1 alert, got %d", len(alerts))
	}

	// Same package, same risk: the entry is KNOWN now, so it must not re-alert.
	if _, err := a.Scan(context.Background(), app.ScanOptions{}); err != nil {
		t.Fatalf("second scan: %v", err)
	}
	alerts, err = store.UnresolvedAlerts()
	if err != nil {
		t.Fatalf("alerts after second scan: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("KNOWN rescan must not add alerts, got %d", len(alerts))
	}
}

// TestApp_ScanAlertsOnEscalation covers the other half of the rule: a
// previously benign observation that has since worsened is CHANGED, and that
// is exactly the event that should notify again.
func TestApp_ScanAlertsOnEscalation(t *testing.T) {
	fake := &fakeRegistry{
		name: domain.RegistryNpm,
		collide: map[string]*domain.PackageInfo{
			"evil-dep": {
				Name:      "evil-dep",
				Registry:  domain.RegistryNpm,
				Version:   "1.0.0",
				CreatedAt: time.Now(),
			},
		},
	}
	a, store := newTestApp(t, fake)

	// Seed a previous benign observation so the next scan sees a change.
	if err := store.RecordEvent(&domain.ScanEntry{
		PackageName: "evil-dep",
		Ecosystem:   domain.EcosystemNpm,
		Registry:    domain.RegistryNpm,
		Status:      domain.StatusKnown,
		Risk:        domain.RiskInfo,
		LastSeen:    time.Now(),
	}); err != nil {
		t.Fatalf("seed previous event: %v", err)
	}

	res, err := a.Scan(context.Background(), app.ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var changed bool
	for _, e := range res.Entries {
		if e.PackageName == "evil-dep" {
			changed = e.Status == domain.StatusChanged
		}
	}
	if !changed {
		t.Fatal("evil-dep should be CHANGED after a benign prior observation")
	}

	alerts, err := store.UnresolvedAlerts()
	if err != nil {
		t.Fatalf("alerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("escalation should add 1 alert, got %d", len(alerts))
	}
}

// TestApp_ScanLogsAlertDeliveryFailure guards the reliability fix: a broken
// webhook must not abort a scan (the alert is already persisted), but it must be
// visible in the log instead of vanishing. The test points the webhook at a
// server that always returns 500, then checks the scan succeeds and logs it.
func TestApp_ScanLogsAlertDeliveryFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("DEPWATCH_TEST_SLACK_WEBHOOK", srv.URL)

	fake := &fakeRegistry{
		name: domain.RegistryNpm,
		collide: map[string]*domain.PackageInfo{
			"evil-dep": {
				Name:      "evil-dep",
				Registry:  domain.RegistryNpm,
				Version:   "1.0.0",
				CreatedAt: time.Now(),
			},
		},
	}

	path := filepath.Join(t.TempDir(), "app_test.db")
	store, err := storage.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	cfg := &config.Config{
		Organization: "test",
		Ecosystems:   map[string][]string{"npm": {"evil-dep"}},
		Registries:   map[string]*config.RegistryConfig{"npm": {Enabled: true}},
		Alerts: config.AlertConfig{Slack: config.SlackConfig{
			Enabled:    true,
			WebhookEnv: "DEPWATCH_TEST_SLACK_WEBHOOK",
		}},
	}
	cfg.ApplyDefaults()
	a := app.New(cfg, []registry.Registry{fake}, store)

	original := log.Writer()
	t.Cleanup(func() { log.SetOutput(original) })
	var logs bytes.Buffer
	log.SetOutput(&logs)

	if _, err := a.Scan(context.Background(), app.ScanOptions{}); err != nil {
		t.Fatalf("scan must survive a delivery failure: %v", err)
	}
	if !strings.Contains(logs.String(), "alert delivery failed") {
		t.Fatalf("expected delivery failure in log, got %q", logs.String())
	}
}

func TestApp_ScanSafeWhenNoPublicMatch(t *testing.T) {
	fake := &fakeRegistry{name: domain.RegistryNpm, collide: map[string]*domain.PackageInfo{}}
	a, _ := newTestApp(t, fake)
	res, err := a.Scan(context.Background(), app.ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, e := range res.Entries {
		if e.Status != domain.StatusSafe {
			t.Fatalf("expected all safe, got %+v", e)
		}
	}
}

// TestApp_ScanRejectsUnknownEcosystem pins the fail-fast fix: a typo like
// --ecosystem npmm must error instead of succeeding emptily with "0 packages".
// A valid ecosystem (any casing) must still scan normally.
func TestApp_ScanRejectsUnknownEcosystem(t *testing.T) {
	fake := &fakeRegistry{name: domain.RegistryNpm, collide: map[string]*domain.PackageInfo{}}
	a, _ := newTestApp(t, fake)

	if _, err := a.Scan(context.Background(), app.ScanOptions{Ecosystem: "npmm"}); err == nil {
		t.Fatal("expected error for unknown ecosystem, got nil")
	}

	for _, eco := range []string{"npm", "NPM", " npm "} {
		if _, err := a.Scan(context.Background(), app.ScanOptions{Ecosystem: eco}); err != nil {
			t.Fatalf("ecosystem %q should scan, got error: %v", eco, err)
		}
	}
}

// TestApp_ScanEntriesSorted pins the stable-output fix: entries must come back
// in (package, registry) order no matter what order workers finish in. It scans
// repeatedly because a single run could pass by luck on the old code (workers
// sometimes happen to finish alphabetically).
func TestApp_ScanEntriesSorted(t *testing.T) {
	fake := &fakeRegistry{
		name: domain.RegistryNpm,
		collide: map[string]*domain.PackageInfo{
			"evil-dep": {
				Name:      "evil-dep",
				Registry:  domain.RegistryNpm,
				Version:   "1.0.0",
				CreatedAt: time.Now(),
			},
		},
	}
	a, _ := newTestApp(t, fake)
	for i := 0; i < 20; i++ {
		res, err := a.Scan(context.Background(), app.ScanOptions{})
		if err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
		for j := 1; j < len(res.Entries); j++ {
			prev, cur := res.Entries[j-1], res.Entries[j]
			if prev.PackageName > cur.PackageName ||
				(prev.PackageName == cur.PackageName && prev.Registry > cur.Registry) {
				t.Fatalf("scan %d: entries not sorted: %s (%s) before %s (%s)",
					i, prev.PackageName, prev.Registry, cur.PackageName, cur.Registry)
			}
		}
	}
}
