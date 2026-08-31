package output

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// LiveScan renders the scan as one in-place updating frame on normal stdout.
//
// Design decisions (all deliberate, see ui_mock.py prototype):
//   - No alternate screen: the finished report stays in scrollback
//   - Rows listed up front as "queued", then animated through stages
//   - Cursor rewinding via ANSI escapes (\033[<n>A + \033[J) for in-place redraw
//   - Doki mascot blinks, gold braille spinner cycles, pulse dot breathes
//   - Plain-language stage names ("asking the registry", "weighing signals")
//   - Closing verdict in doki's voice
//
// Thread safety: Event() and Render() may be called from different goroutines.
// The mutex protects all mutable state; the frame is built atomically.
type LiveScan struct {
	mu     sync.Mutex
	w      io.Writer
	stats  LiveStats
	states map[string]*liveState
	order  []string
	spin   int
	start  time.Time
	lines  int // height of the previously drawn frame, for the rewind
	done   bool
}

// liveState tracks one lookup. pkg/reg are stored explicitly rather than parsed back
// out of the map key: scoped npm names begin with '@' (e.g. "@acme/scheduler"), so
// splitting a "pkg@reg" key would yield an empty package name for them.
type liveState struct {
	pkg       string
	reg       string
	phase     domain.ScanPhase
	status    domain.ScanStatus
	risk      domain.RiskLevel
	threat    domain.ThreatLevel
	signals   []domain.Signal
	collision *domain.Collision
	firstSeen time.Time
	err       string
}

// LiveStats carries the header metadata. Plain data, so the renderer never imports
// the config package.
type LiveStats struct {
	Org        string
	Registries string
	Inventory  int
	Workers    int
	Store      string
	Version    string
	// Full enables the verbose per-finding evidence block (scan --full).
	Full bool
}

// LiveItem is one planned (package × registry) lookup, listed as "queued" before the
// scan starts so the user sees the full work set immediately.
type LiveItem struct {
	Pkg string
	Reg string
}

// gold dotted spinner (braille) and a breathing pulse dot, so the frame stays alive
// even when a slow registry means no row has changed for a beat.
var (
	liveSpin    = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	pulseFrames = []string{"·", "•", "●", "•"}
)

// stageWords describe each phase in plain language, so the user always knows which
// step a package is on instead of staring at an opaque spinner.
var stageWords = map[domain.ScanPhase]string{
	domain.PhaseQueued:    "queued",
	domain.PhaseQuerying:  "asking the registry",
	domain.PhaseAnalyzing: "weighing signals",
}

// NewLiveScan creates a LiveScan renderer. items define the full work set so the
// renderer can show "queued" rows before work starts. stats supply the header
// metadata (org, registries, inventory size, worker count, store path). The
// renderer does not import config — all data flows through these plain structs.
func NewLiveScan(w io.Writer, stats LiveStats, items []LiveItem) *LiveScan {
	l := &LiveScan{
		w: w, stats: stats,
		states: make(map[string]*liveState, len(items)),
		start:  time.Now(),
	}
	for _, it := range items {
		key := it.Pkg + "\x00" + it.Reg
		l.states[key] = &liveState{pkg: it.Pkg, reg: it.Reg, phase: domain.PhaseQueued}
		l.order = append(l.order, key)
	}
	return l
}

// Start paints the first frame, with every lookup shown as queued.
func (l *LiveScan) Start() { l.Render() }

// Event folds a progress event into the tracked state. Safe to call from the scan
// goroutine; Render holds the lock while reading.
func (l *LiveScan) Event(e domain.ProgressEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := e.Package + "\x00" + string(e.Registry)
	st := l.states[key]
	if st == nil {
		st = &liveState{pkg: e.Package, reg: string(e.Registry)}
		l.states[key] = st
		l.order = append(l.order, key)
	}
	st.phase = e.Phase
	switch e.Phase {
	case domain.PhaseDone:
		st.status, st.risk, st.signals = e.Status, e.Risk, e.Signals
		st.threat = e.Threat
		st.collision, st.firstSeen = e.Collision, e.FirstSeen
	case domain.PhaseError:
		st.err = e.Error
	}
}

// Tick advances the spinner, the pulse and doki's blink.
func (l *LiveScan) Tick() {
	l.mu.Lock()
	l.spin++
	l.mu.Unlock()
}

// Finish draws the closing frame, including doki's verdict, and stops rewinding so
// the report stays put in the scrollback.
func (l *LiveScan) Finish() {
	l.mu.Lock()
	l.done = true
	l.mu.Unlock()
	l.Render()
}

// Render redraws the frame in place: rewind over the previous frame, erase downward,
// then paint. Erasing to the end of the screen means rows that grow (collision signal
// lines) or shrink can never leave ghost text behind.
func (l *LiveScan) Render() {
	l.mu.Lock()
	defer l.mu.Unlock()
	frame := l.frameLocked()
	if l.lines > 0 {
		fmt.Fprintf(l.w, "\033[%dA", l.lines)
	}
	fmt.Fprint(l.w, "\033[J")
	for _, line := range frame {
		fmt.Fprintln(l.w, line)
	}
	l.lines = len(frame)
}

// frameLocked builds every line of the current frame. Caller must hold l.mu.
func (l *LiveScan) frameLocked() []string {
	var b strings.Builder
	writeBanner(&b, l.stats, DOKI[(l.spin/6)%len(DOKI)])

	done, live, hits, crit := 0, 0, 0, 0
	var errs []string
	for _, k := range l.order {
		st := l.states[k]
		switch st.phase {
		case domain.PhaseQuerying, domain.PhaseAnalyzing:
			live++
		case domain.PhaseError:
			done++
			errs = append(errs, fmt.Sprintf("%s: %s", st.reg, st.err))
		case domain.PhaseDone:
			done++
			if st.status != domain.StatusSafe {
				hits++
				if st.risk == domain.RiskCritical {
					crit++
				}
			}
		}
	}

	b.WriteString(l.statusLine(done, live, hits, crit))
	b.WriteString("\n\n")
	writeTableHeader(&b)
	for _, k := range l.order {
		l.rowLocked(&b, l.states[k])
	}
	b.WriteString("\n")
	writeSummary(&b, len(l.order), hits, crit, errs)
	if l.done {
		b.WriteString(dimStyle.Render("  " + l.verdict(hits, crit, len(errs))))
		b.WriteString("\n")
	}
	return strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
}

// statusLine narrates the run: a breathing pulse, progress, how many lookups are in
// the air, the running find count (escalating to red on a critical) and the clock.
func (l *LiveScan) statusLine(done, live, hits, crit int) string {
	took := time.Since(l.start).Seconds()
	if l.done {
		return dimStyle.Render(fmt.Sprintf("  doki is done · [%d/%d] · %.1fs", done, len(l.order), took))
	}
	found := dimStyle.Render(fmt.Sprintf("%d found", hits))
	if crit > 0 {
		found = riskStyles[domain.RiskCritical].Render(fmt.Sprintf("%d found, %d critical", hits, crit))
	}
	return "  " + spinStyle.Render(pulseFrames[(l.spin/2)%len(pulseFrames)]) + " " +
		dimStyle.Render(fmt.Sprintf("doki is sniffing · [%d/%d] · %d in flight · ", done, len(l.order), live)) +
		found + dimStyle.Render(fmt.Sprintf(" · %.1fs", took))
}

// rowLocked writes one table row for the state's current phase.
func (l *LiveScan) rowLocked(b *strings.Builder, st *liveState) {
	switch st.phase {
	case domain.PhaseDone:
		e := domain.ScanEntry{
			PackageName: st.pkg, Registry: domain.RegistryName(st.reg),
			Status: st.status, Risk: st.risk, Signals: st.signals,
			Threat: st.threat, Collision: st.collision, FirstSeen: st.firstSeen,
		}
		if l.stats.Full {
			writeRow(b, e)
			writeDetails(b, e)
			b.WriteString("\n")
		} else {
			writeTableRow(b, e)
			if len(e.Signals) > 0 {
				b.WriteString("\n")
			}
		}
		if st.status != domain.StatusSafe && st.risk == domain.RiskCritical {
			fmt.Fprintln(b, riskStyles[domain.RiskCritical].Render(
				"      doki bristles: this name is already taken in public. go look, now."))
		}
	case domain.PhaseError:
		fmt.Fprintf(b, "%-3s %-34s %-8s %s %s\n",
			statusIcon[domain.StatusChanged], st.pkg, registryCell(domain.RegistryName(st.reg), 10),
			dimStyle.Render(fmt.Sprintf("%-9s", "ERROR")), dimStyle.Render(st.err))
	case domain.PhaseQuerying, domain.PhaseAnalyzing:
		fmt.Fprintf(b, "%s %-34s %s %s\n",
			gutter(spinStyle, liveSpin[l.spin%len(liveSpin)]), st.pkg, registryCell(domain.RegistryName(st.reg), 10),
			dimStyle.Render(stageWords[st.phase]))
	default:
		fmt.Fprintf(b, "%s %-34s %s %s\n",
			gutter(dimStyle, "·"), st.pkg, registryCell(domain.RegistryName(st.reg), 10),
			dimStyle.Render(stageWords[domain.PhaseQueued]))
	}
}

// gutter renders a status glyph in the 3-wide icon column. The glyph is padded while
// still plain text, because fmt counts the styled string's ANSI escapes as runes and
// would otherwise never pad it — which visibly knocked spinner rows out of alignment
// against the plain check marks.
func gutter(s lipgloss.Style, glyph string) string {
	return s.Render(fmt.Sprintf("%-3s", glyph))
}

// verdict is doki's plain-language read on the finished run.
func (l *LiveScan) verdict(hits, crit, errs int) string {
	took := time.Since(l.start).Seconds()
	switch {
	case crit > 0:
		return fmt.Sprintf("doki found %d impostor(s), %d critical, in %.1fs. that is dependency confusion — claim those names.", hits, crit, took)
	case hits > 0:
		return fmt.Sprintf("doki found %d name(s) also living in public in %.1fs. worth a look.", hits, took)
	case errs > 0:
		return fmt.Sprintf("doki sniffed %d packages in %.1fs; some registries would not answer.", len(l.order)-errs, took)
	default:
		return fmt.Sprintf("doki sniffed all %d packages in %.1fs and found nothing sketchy. purring.", len(l.order), took)
	}
}
