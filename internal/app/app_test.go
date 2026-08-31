package app_test

import (
	"context"
	"path/filepath"
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
