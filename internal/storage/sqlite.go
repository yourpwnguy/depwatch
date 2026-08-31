// Package storage persists scan observations and alerts using SQLite.
//
// The implementation uses modernc.org/sqlite (pure Go, no CGO) so the binary
// stays statically linkable and the database is just one file. The schema is
// append-only by design: each scan inserts new rows rather than updating existing
// ones, so history is fully preserved across runs.
//
// Two tables:
//   - scan_events: append-only scan observations, indexed by (package, registry)
//   - alerts: notification records with a resolved flag for lifecycle management
//
// Swapping to Postgres or another backend in the future means writing a new Store
// against the same method set — no caller changes needed. The domain types are the
// only contract.
package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// Store is the SQLite-backed persistence layer. It is safe for concurrent use
// by the scan pipeline's worker pool, enforced by MaxOpenConns(1) which serializes
// all writes to the local file.
type Store struct {
	db *sql.DB
}

// schema is applied idempotently on Open. The scan_events table is append-only:
// each scan inserts a new row; Latest() reads the most recent via ORDER BY id DESC.
// The alerts table tracks resolution state so `depwatch alerts` can list outstanding
// notifications without re-deriving them from scan history.
const schema = `
CREATE TABLE IF NOT EXISTS scan_events (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	package_name TEXT NOT NULL,
	ecosystem    TEXT NOT NULL,
	registry     TEXT NOT NULL,
	status       TEXT NOT NULL,
	risk         TEXT NOT NULL,
	version      TEXT,
	publisher    TEXT,
	downloads    INTEGER,
	scanned_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_pkg ON scan_events(package_name, registry);

CREATE TABLE IF NOT EXISTS alerts (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	package_name TEXT NOT NULL,
	registry     TEXT NOT NULL,
	risk         TEXT NOT NULL,
	type         TEXT NOT NULL,
	created_at   INTEGER NOT NULL,
	resolved     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts(resolved, package_name);
`

// Open opens (creating if needed) the SQLite database at path and applies the
// schema. A single connection (MaxOpenConns=1) avoids locking surprises on the
// local file database and is sufficient for the append-only write pattern.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database %q: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the database handle. It is safe to call once after all operations
// complete.
func (s *Store) Close() error { return s.db.Close() }

// scanEntry scans a single scan_events row into a domain.ScanEntry. Collision is
// left nil for stored observations — the full collision is only meaningful during
// the active scan and is not persisted. FirstSeen is approximated from the scanned_at
// timestamp; this is the proxy noted in HANDOFF item #4.
func scanEntry(row *sql.Row) (*domain.ScanEntry, error) {
	var (
		name, eco, reg, status, risk, version, publisher string
		downloads                                        int64
		scanned                                          int64
	)
	if err := row.Scan(&name, &eco, &reg, &status, &risk, &version, &publisher, &downloads, &scanned); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("scan entry: %w", err)
	}
	return &domain.ScanEntry{
		PackageName: name,
		Ecosystem:   domain.Ecosystem(eco),
		Registry:    domain.RegistryName(reg),
		Status:      domain.ScanStatus(status),
		Risk:        domain.RiskLevel(risk),
		Version:     version,
		Publisher:   publisher,
		Downloads:   downloads,
		LastSeen:    time.Unix(scanned, 0),
		FirstSeen:   time.Unix(scanned, 0),
	}, nil
}

// collectEntries iterates a result set and collects domain.ScanEntry values.
// The row-scanning logic is shared with scanEntry to avoid duplication while
// supporting both single-row (Latest) and multi-row (History) queries.
func collectEntries(rows *sql.Rows) ([]domain.ScanEntry, error) {
	var out []domain.ScanEntry
	for rows.Next() {
		var (
			name, eco, reg, status, risk, version, publisher string
			downloads                                        int64
			scanned                                          int64
		)
		if err := rows.Scan(&name, &eco, &reg, &status, &risk, &version, &publisher, &downloads, &scanned); err != nil {
			return nil, fmt.Errorf("scan entry: %w", err)
		}
		out = append(out, domain.ScanEntry{
			PackageName: name,
			Ecosystem:   domain.Ecosystem(eco),
			Registry:    domain.RegistryName(reg),
			Status:      domain.ScanStatus(status),
			Risk:        domain.RiskLevel(risk),
			Version:     version,
			Publisher:   publisher,
			Downloads:   downloads,
			LastSeen:    time.Unix(scanned, 0),
			FirstSeen:   time.Unix(scanned, 0),
		})
	}
	return out, rows.Err()
}
