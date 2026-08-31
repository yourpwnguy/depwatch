// Package output renders scan results for the terminal and for machines. It depends
// only on domain types and lipgloss for styling; it never performs I/O decisions or
// business logic, so the core stays free of presentation concerns.
//
// Three renderers share one set of primitives:
//   - human.go: static report (WriteReport, WriteHistory, WriteAlerts, WriteInventory)
//   - live.go: animated scan view (LiveScan) with in-place terminal updates
//   - json.go: machine-readable JSON output (WriteJSON, WriteAlertsJSON)
//
// All terminal rendering flows through the shared primitives in report.go, which
// define the column layout, evidence tree, and summary footer. This single source
// of truth prevents the static and animated views from drifting out of alignment.
package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// WriteJSON encodes the scan result as indented JSON to w. It is the machine
// readable path used for piping into jq, CI systems, and other tooling. The
// indentation makes the output human-debuggable without requiring a formatter.
func WriteJSON(w io.Writer, res *domain.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

// WriteAlertsJSON encodes a list of alerts as JSON. Used by `depwatch alerts --format json`.
func WriteAlertsJSON(w io.Writer, alerts []domain.Alert) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(alerts)
}
