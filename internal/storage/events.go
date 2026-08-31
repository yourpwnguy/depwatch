package storage

import (
	"fmt"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// RecordEvent appends one scan observation to the scan_events table. History is
// preserved because each scan inserts a new row rather than updating an existing
// one; Latest() reads the most recent row via ORDER BY id DESC LIMIT 1.
//
// The scanned_at timestamp comes from ScanEntry.LastSeen, which is set to time.Now()
// by the scan pipeline at lookup completion.
func (s *Store) RecordEvent(e *domain.ScanEntry) error {
	_, err := s.db.Exec(`
		INSERT INTO scan_events (package_name, ecosystem, registry, status, risk, version, publisher, downloads, scanned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.PackageName, string(e.Ecosystem), string(e.Registry),
		string(e.Status), string(e.Risk), e.Version, e.Publisher, e.Downloads,
		e.LastSeen.Unix(),
	)
	if err != nil {
		return fmt.Errorf("record event: %w", err)
	}
	return nil
}

// Latest returns the most recent observation for a (package, registry) pair, or
// nil if none exists. It is used by the scan pipeline to compute NEW/KNOWN/CHANGED
// status by comparing the current assessment against the previous one.
func (s *Store) Latest(name string, registry string) (*domain.ScanEntry, error) {
	row := s.db.QueryRow(`
		SELECT package_name, ecosystem, registry, status, risk, version, publisher, downloads, scanned_at
		FROM scan_events WHERE package_name = ? AND registry = ?
		ORDER BY id DESC LIMIT 1`, name, registry)
	return scanEntry(row)
}

// History returns all observations for a package name across all registries,
// ordered newest first. Used by `depwatch history <name>` to show the temporal
// evolution of a collision's risk assessment.
func (s *Store) History(name string) ([]domain.ScanEntry, error) {
	rows, err := s.db.Query(`
		SELECT package_name, ecosystem, registry, status, risk, version, publisher, downloads, scanned_at
		FROM scan_events WHERE package_name = ? ORDER BY id DESC`, name)
	if err != nil {
		return nil, fmt.Errorf("history query: %w", err)
	}
	defer rows.Close()
	return collectEntries(rows)
}

// RecordEvents is a convenience for persisting multiple entries. It does not
// transactionalize the writes — partial persistence is acceptable because the
// scan pipeline already handles partial registry failures gracefully.
func (s *Store) RecordEvents(entries []domain.ScanEntry) error {
	for i := range entries {
		if err := s.RecordEvent(&entries[i]); err != nil {
			return err
		}
	}
	return nil
}
