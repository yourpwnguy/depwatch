// Package app is the orchestration layer. It owns the registries, store, and alert
// configuration and runs the scan pipeline. It contains no CLI or output-formatting
// logic, which keeps the domain decisions testable and the presentation separate.
package app

import (
	"context"
	"time"

	"github.com/yourpwnguy/depwatch/internal/alerting"
	"github.com/yourpwnguy/depwatch/internal/config"
	"github.com/yourpwnguy/depwatch/internal/domain"
	"github.com/yourpwnguy/depwatch/internal/registry"
	"github.com/yourpwnguy/depwatch/internal/storage"
)

// App coordinates a scan: it fans inventory entries out to registries via a bounded
// worker pool, persists observations, and raises alerts when risk crosses threshold.
type App struct {
	cfg      *config.Config
	regs     []registry.Registry
	store    *storage.Store
	alertEnv string
}

// New constructs an App. registries must correspond to the enabled registries in
// cfg; store must be open. alertEnv is the env var holding the Slack webhook (empty
// disables Slack notifications).
func New(cfg *config.Config, regs []registry.Registry, store *storage.Store) *App {
	env := ""
	if cfg.Alerts.Slack.Enabled {
		env = cfg.Alerts.Slack.WebhookEnv
	}
	return &App{cfg: cfg, regs: regs, store: store, alertEnv: env}
}

// Close releases the underlying store. It is safe to call once after use.
func (a *App) Close() error { return a.store.Close() }

// ScanOptions tunes a single scan run.
type ScanOptions struct {
	// Ecosystem, when non-empty, restricts the scan to that ecosystem only.
	Ecosystem string
	// AllRegistries, when true, sends each package to every enabled registry instead
	// of just the one matching its ecosystem. Used by the `package` investigation
	// command, where the user explicitly wants to check a name everywhere.
	AllRegistries bool
	// Progress, when non-nil, receives a domain.ProgressEvent for every phase
	// transition of each (package × registry) lookup. The CLI uses it to render a
	// live view. It is never invoked from app-internal tests, so nil is the default
	// and the pipeline skips all event work when it is nil.
	Progress func(domain.ProgressEvent)
}

// Scan runs a full scan over the configured inventory, persists every observation,
// and fires alerts for any entry crossing the configured alert threshold. It never
// fails the whole run because one registry errored — such errors surface as
// res.Partial and the caller must not treat missing entries as safe.
func (a *App) Scan(ctx context.Context, opts ScanOptions) (*domain.ScanResult, error) {
	pkgs := a.cfg.InternalPackages()
	if opts.Ecosystem != "" {
		pkgs = filterByEcosystem(pkgs, opts.Ecosystem)
	}

	res, err := a.scanPipeline(ctx, pkgs, opts)
	if err != nil {
		return nil, err
	}

	for i := range res.Entries {
		e := &res.Entries[i]
		if err := a.store.RecordEvent(e); err != nil {
			return nil, err
		}
		if isAlertable(e, a.cfg.Thresholds.Alert) {
			alert := toAlert(e)
			if err := a.store.AddAlert(alert); err != nil {
				return nil, err
			}
			if a.alertEnv != "" {
				// Alert delivery failures must not abort the scan; log-and-continue
				// is correct because the alert is already persisted.
				_ = alerting.Send(ctx, a.alertEnv, alert)
			}
		}
	}
	return res, nil
}

// Package investigates a single package name across all enabled registries,
// returning one entry per registry. Useful for `depwatch package <name>`.
func (a *App) Package(ctx context.Context, name string) (*domain.ScanResult, error) {
	pkgs := a.cfg.InternalPackages()
	var target *domain.InternalPackage
	for i := range pkgs {
		if pkgs[i].Name == name {
			target = &pkgs[i]
			break
		}
	}
	if target == nil {
		// Fall back to scanning the bare name across every enabled registry using a
		// synthetic package with unknown ecosystem; detection still works on name.
		target = &domain.InternalPackage{Name: name}
	}
	return a.scanPipeline(ctx, []domain.InternalPackage{*target}, ScanOptions{AllRegistries: true})
}

// History returns stored observations for a package.
func (a *App) History(ctx context.Context, name string) ([]domain.ScanEntry, error) {
	return a.store.History(name)
}

// Alerts returns unresolved alerts.
func (a *App) Alerts(ctx context.Context) ([]domain.Alert, error) {
	return a.store.UnresolvedAlerts()
}

// CI runs a scan and returns a result suitable for CI gating. The caller decides
// the exit code based on whether any entry meets the block_ci threshold.
func (a *App) CI(ctx context.Context) (*domain.ScanResult, error) {
	return a.Scan(ctx, ScanOptions{})
}

func filterByEcosystem(pkgs []domain.InternalPackage, eco string) []domain.InternalPackage {
	var out []domain.InternalPackage
	for _, p := range pkgs {
		if string(p.Ecosystem) == eco {
			out = append(out, p)
		}
	}
	return out
}

// isAlertable reports whether an entry should raise a notification. Safe entries
// never alert; everything else alerts when its risk meets the threshold.
func isAlertable(e *domain.ScanEntry, threshold string) bool {
	if e.Status == domain.StatusSafe {
		return false
	}
	return domain.RiskAtLeast(e.Risk, domain.RiskLevel(threshold))
}

// toAlert converts a scan entry into a persisted alert.
func toAlert(e *domain.ScanEntry) *domain.Alert {
	typ := domain.AlertNewCollision
	if e.Status == domain.StatusChanged {
		typ = domain.AlertRiskEscalation
	}
	return &domain.Alert{
		PackageName: e.PackageName,
		Registry:    e.Registry,
		Risk:        e.Risk,
		Type:        typ,
		CreatedAt:   time.Now(),
		Signals:     e.Signals,
	}
}
