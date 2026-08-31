package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/yourpwnguy/depwatch/internal/domain"
)

// catStyle colors the doki mascot and the live spinner gold, matching the
// UI prototype's palette. statCyan/statWhite color the header stat values so the
// banner reads as structured tool metadata rather than loud decoration.
var (
	catStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	spinStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	statCyan  = lipgloss.NewStyle().Foreground(lipgloss.Color("75"))
	statWhite = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
)

// DOKI frames cycle to animate the mascot during a live scan. Frame 0 is the calm
// resting face used by the static report renderers (monitor, package, non-TTY scan),
// so the brand is consistent everywhere without motion. The mascot is deliberately
// simple (ASCII art) so it renders correctly on any terminal without Unicode issues.
var DOKI = [][3]string{
	{"/\\_/\\", "( o.o )", "> ^ <"},
	{"/\\_/\\", "( -.- )", "> ^ <"},
	{"/\\_/\\", "( O.O )", "> o <"},
	{"/\\_/\\", "( o.o )", "> ~ <"},
}

// writeBanner renders the doki mascot, the tool identity, and the live stats block.
// cat supplies the (possibly animated) frame; callers pass DOKI[0] for a static view.
// The banner establishes the visual hierarchy: mascot + tool name at top, then
// structured metadata (org, registries, inventory, workers, store) below.
func writeBanner(w io.Writer, stats LiveStats, cat [3]string) {
	fmt.Fprintln(w, catStyle.Render("  "+cat[0])+"   "+titleStyle.Render("depwatch")+dimStyle.Render("  dependency confusion monitor"))
	fmt.Fprintln(w, catStyle.Render(" "+cat[1])+"  "+dimStyle.Render(fmt.Sprintf("v%s   scanning internal packages against public registries", stats.Version)))
	fmt.Fprintln(w, catStyle.Render("  "+cat[2]))
	fmt.Fprintln(w)
	fmt.Fprintln(w, dimStyle.Render("  org         ")+statCyan.Render(stats.Org))
	fmt.Fprintln(w, dimStyle.Render("  registries  ")+colorRegistryList(stats.Registries))
	fmt.Fprintln(w, dimStyle.Render("  inventory   ")+statWhite.Render(fmt.Sprintf("%d internal packages", stats.Inventory)))
	fmt.Fprintln(w, dimStyle.Render("  workers     ")+statWhite.Render(fmt.Sprintf("%d concurrent lookups", stats.Workers)))
	fmt.Fprintln(w, dimStyle.Render("  store       ")+statWhite.Render(stats.Store))
	fmt.Fprintln(w)
}

// writeTableHeader prints the column labels in the report's bold-grey header style,
// using the exact same field widths as the rows so columns line up. The widths are
// chosen to accommodate realistic data: 34 chars for scoped npm names, 10 for
// registry names, 9 for risk levels, 11 for threat levels.
func writeTableHeader(w io.Writer) {
	fmt.Fprintln(w, headerStyle.Render(fmt.Sprintf("%-3s %-34s %-10s %-9s %-11s %s", "  ", "PACKAGE", "REGISTRY", "RISK", "THREAT", "SIGNALS")))
}

// writeTableRow prints one finished lookup: the status line plus its signals as the
// same indented evidence tree the verbose mode uses, so both views share one visual
// language. The branch is closed here because no further sections follow.
func writeTableRow(w io.Writer, e domain.ScanEntry) {
	writeRow(w, e)
	writeEvidence(w, e, "└")
}

// writeSummary prints the running tally "N packages · M collisions · K critical",
// adding a PARTIAL note (in orange) with the per-registry error lines when some
// lookups failed. This is the shared footer for both the live and static reports.
func writeSummary(w io.Writer, total, collisions, critical int, partialErrs []string) {
	summary := fmt.Sprintf("%d packages · %d collisions · %d critical", total, collisions, critical)
	if len(partialErrs) > 0 {
		summary += " · " + lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render(fmt.Sprintf("PARTIAL (%d lookup errors)", len(partialErrs)))
	}
	fmt.Fprintln(w, headerStyle.Render(summary))
	if len(partialErrs) > 0 {
		for _, e := range partialErrs {
			fmt.Fprintln(w, dimStyle.Render("  ! "+e))
		}
	}
}

// sevStyles map signal severities to the risk palette, so a HIGH signal reads
// the same color everywhere in the tool. This reuses the risk styles from human.go
// to maintain visual consistency across the entire output.
var sevStyles = map[domain.SignalSeverity]lipgloss.Style{
	domain.SigHigh: riskStyles[domain.RiskHigh],
	domain.SigMed:  riskStyles[domain.RiskMedium],
	domain.SigLow:  riskStyles[domain.RiskLow],
}

// threatStyles color the threat verdict: green means "collision, but looks
// legitimate", orange means "worth a look", red means "investigate now".
// regStyles color each registry in its own brand hue — npm red, PyPI steel blue,
// crates.io rust orange — so an ecosystem is recognizable before the name is read.
var regStyles = map[domain.RegistryName]lipgloss.Style{
	domain.RegistryNpm:    lipgloss.NewStyle().Foreground(lipgloss.Color("160")),
	domain.RegistryPypi:   lipgloss.NewStyle().Foreground(lipgloss.Color("74")),
	domain.RegistryCrates: lipgloss.NewStyle().Foreground(lipgloss.Color("208")),
}

// registryCell renders a registry name in its brand color, padded to w while still
// plain text so the ANSI escapes cannot eat the column padding. The padding rule
// (critical): fmt's %-Ns counts runes, so a lipgloss-styled string never pads
// correctly. Always pad the plain text first, then style it.
func registryCell(r domain.RegistryName, w int) string {
	return regStyles[r].Render(fmt.Sprintf("%-*s", w, string(r)))
}

var threatStyles = map[domain.ThreatLevel]lipgloss.Style{
	domain.ThreatBenign:     lipgloss.NewStyle().Foreground(lipgloss.Color("82")),
	domain.ThreatSuspicious: lipgloss.NewStyle().Foreground(lipgloss.Color("214")),
	domain.ThreatDangerous:  lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")),
}

var (
	guideStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	keyStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
)

// writeRow prints just the status line of an entry, without its signal list. The
// verbose view uses this because writeDetails re-states the signals with more context,
// and printing both was the duplication that made --full feel cluttered. The row format
// is: STATUS PACKAGE REGISTRY RISK THREAT SIGNALS — padded to fixed column widths.
func writeRow(w io.Writer, e domain.ScanEntry) {
	fmt.Fprintf(w, "%-3s %-34s %s %s %s %s\n",
		statusIcon[e.Status], e.PackageName, registryCell(e.Registry, 10),
		riskStyles[e.Risk].Render(fmt.Sprintf("%-9s", string(e.Risk))),
		threatStyles[e.Threat].Render(fmt.Sprintf("%-11s", threatWord(e.Threat))),
		dimStyle.Render(signalCount(len(e.Signals))))
}

// signalCount renders the signal count as a human-friendly string: "clean" for
// zero, "1 signal" for one, "N signals" for multiple.
func signalCount(n int) string {
	switch n {
	case 0:
		return "clean"
	case 1:
		return "1 signal"
	default:
		return fmt.Sprintf("%d signals", n)
	}
}

// writeEvidence prints an entry's signals as the same indented tree used by --full,
// so normal and verbose modes read identically — only the amount of context differs.
// last is the guide for the final line, letting the caller close the branch when no
// further sections follow. Each signal is prefixed with its severity in the
// appropriate risk color, followed by the pretty-printed code and optional detail.
func writeEvidence(w io.Writer, e domain.ScanEntry, last string) {
	for i, s := range e.Signals {
		label, guide := "", "│"
		if i == 0 {
			label = "evidence"
		}
		if i == len(e.Signals)-1 {
			guide = last
		}
		text := prettyCode(s)
		if s.Detail != "" {
			text += dimStyle.Render("  ·  " + s.Detail)
		}
		branch(w, guide, label, sevStyles[s.Severity].Render(fmt.Sprintf("%-4s", s.Severity))+" "+text)
	}
}

// writeDetails prints the full evidence block for one entry as a small indented
// tree, shown by `scan --full`. Everything here was already fetched during the
// lookup, so verbosity costs no extra requests; it exists so an analyst can judge
// a finding without leaving the terminal. Facts are folded onto few dense lines
// rather than one label per row, which is what kept the earlier version from
// feeling tidy.
func writeDetails(w io.Writer, e domain.ScanEntry) {
	if e.Collision == nil {
		branch(w, "└", "clean", fmt.Sprintf("no public package named %s on %s", e.PackageName, e.Registry))
		return
	}
	p := e.Collision.Public

	facts := []string{p.Version}
	if !p.CreatedAt.IsZero() {
		facts = append(facts, fmt.Sprintf("%dd old", int(time.Since(p.CreatedAt).Hours()/24)))
	}
	facts = append(facts, fieldOr(p.Publisher, "no publisher"))
	if p.Downloads > 0 {
		facts = append(facts, commas(p.Downloads)+" downloads")
	}
	branch(w, "│", "public", strings.Join(compact(facts), dot))
	branch(w, "│", "source", fieldOr(host(p.Repository), "no source published"))

	writeEvidence(w, e, "│")

	hist := []string{"first seen " + e.FirstSeen.Format("2006-01-02 15:04"), strings.ToLower(string(e.Status))}
	branch(w, "└", "history", strings.Join(hist, dot))
}

// threatWord renders the verdict in lower case so the row reads as prose next to the
// upper-case risk level, keeping the two scales visually distinct.
func threatWord(t domain.ThreatLevel) string {
	if t == "" {
		return "—"
	}
	return strings.ToLower(string(t))
}

const dot = "  ·  "

// branch writes one line of the detail tree: guide character, aligned label, value.
// The 9-char label width is fixed to align all branches in the evidence tree.
func branch(w io.Writer, guide, label, value string) {
	fmt.Fprintf(w, "      %s %s %s\n",
		guideStyle.Render(guide), keyStyle.Render(fmt.Sprintf("%-9s", label)), value)
}

// prettyCode turns EXACT_NAME_COLLISION into "exact name collision", which reads
// far better than the raw constant while staying traceable to analyze.go.
func prettyCode(s domain.Signal) string {
	if s.Code == "" {
		return s.Message
	}
	return strings.ToLower(strings.ReplaceAll(s.Code, "_", " "))
}

// host trims a repository URL to its host + path so the line stays short.
// https://github.com/user/repo becomes github.com/user/repo.
func host(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	return strings.TrimSuffix(u, "/")
}

// fieldOr substitutes a spoken fallback for absent metadata. Registries are
// inconsistent about "missing": PyPI emits the literal strings "UNKNOWN"/"None"
// rather than omitting the field, and those must not be shown as real values.
func fieldOr(v, fallback string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "UNKNOWN", "NONE", "NULL", "N/A":
		return fallback
	}
	return v
}

// compact removes empty strings from a slice, preserving order. Used to build
// the dense fact lines in writeDetails where some fields may be absent.
func compact(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// commas makes large download counts readable at a glance: 1234567 → "1,234,567".
func commas(n int64) string {
	s := fmt.Sprintf("%d", n)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// colorRegistryList paints each registry in the banner with its brand color, keeping
// the separator dim so the names stand out. The input is a space-separated list like
// "npm · pypi · crates".
func colorRegistryList(list string) string {
	parts := strings.Split(list, " · ")
	for i, p := range parts {
		name := domain.RegistryName(strings.TrimSpace(p))
		if st, ok := regStyles[name]; ok {
			parts[i] = st.Render(string(name))
		} else {
			parts[i] = statCyan.Render(p)
		}
	}
	return strings.Join(parts, dimStyle.Render(" · "))
}
