package domain

import "time"

// ScanPhase describes the lifecycle of a single (package × registry) lookup as it
// moves through the scan pipeline. These phases are emitted as progress events so a
// terminal renderer can show exactly what is happening (querying the registry,
// analyzing the signals, done) without coupling the app layer to any UI.
type ScanPhase string

const (
	PhaseQueued    ScanPhase = "queued"    // not yet started (pre-populated by the renderer)
	PhaseQuerying  ScanPhase = "querying"  // network request to the registry in flight
	PhaseAnalyzing ScanPhase = "analyzing" // registry responded; running collision + signal analysis
	PhaseDone      ScanPhase = "done"      // lookup finished (see Status for the verdict)
	PhaseError     ScanPhase = "error"     // lookup failed (transport/registry error)
)

// ProgressEvent is a point-in-time update for one lookup. The app emits these from
// the worker pool; the CLI turns them into live output. Keeping the event in the
// domain package means both the producer (app) and the consumer (output) depend only
// on domain, never on each other.
//
// Note: Done/Total counts are intentionally omitted. The renderer tracks completion
// itself from the stream of events (it knows the full job set up front), so sending
// running counters on every event would be redundant bytes on the channel.
type ProgressEvent struct {
	Package  string
	Registry RegistryName
	Phase    ScanPhase
	// Status, Risk, and Signals are only meaningful when Phase == PhaseDone. For a
	// collision they carry the computed verdict; for a safe lookup Status is
	// StatusSafe and Risk/Signals are zero values.
	Status  ScanStatus
	Risk    RiskLevel
	Signals []Signal
	// Collision and FirstSeen carry the full evidence for verbose rendering
	// (scan --full). Collision is nil for a safe lookup.
	Threat    ThreatLevel
	Collision *Collision
	FirstSeen time.Time
	// Error is only meaningful when Phase == PhaseError; it carries the registry
	// failure message so a live renderer can report which lookup failed.
	Error string
}
