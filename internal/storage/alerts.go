package storage

import (
	"fmt"
	"time"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// AddAlert inserts a new unresolved alert. Alerts are created when a scan entry
// crosses the configured alert threshold (see app.Scan). Delivery to external
// sinks (Slack) happens outside this function — the alert is persisted first so
// it survives delivery failures and can be retried.
func (s *Store) AddAlert(a *domain.Alert) error {
	_, err := s.db.Exec(`
		INSERT INTO alerts (package_name, registry, risk, type, created_at, resolved)
		VALUES (?, ?, ?, ?, ?, 0)`,
		a.PackageName, string(a.Registry), string(a.Risk), string(a.Type), a.CreatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("add alert: %w", err)
	}
	return nil
}

// UnresolvedAlerts returns all alerts that have not been marked resolved, ordered
// newest first. The resolved flag is lifecycle-managed: `depwatch alerts` displays
// them, and a future resolve command will flip the flag.
func (s *Store) UnresolvedAlerts() ([]domain.Alert, error) {
	rows, err := s.db.Query(`
		SELECT package_name, registry, risk, type, created_at
		FROM alerts WHERE resolved = 0 ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("unresolved alerts: %w", err)
	}
	defer rows.Close()

	var out []domain.Alert
	for rows.Next() {
		var (
			name, reg, risk, typ string
			created              int64
		)
		if err := rows.Scan(&name, &reg, &risk, &typ, &created); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		out = append(out, domain.Alert{
			PackageName: name,
			Registry:    domain.RegistryName(reg),
			Risk:        domain.RiskLevel(risk),
			Type:        domain.AlertType(typ),
			CreatedAt:   time.Unix(created, 0),
		})
	}
	return out, rows.Err()
}
