package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// Styles are the shared lipgloss definitions for terminal rendering. They are cheap
// to construct and cached at package init, so rendering many rows does not reallocate
// style objects.
var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	dimStyle    = lipgloss.NewStyle().Faint(true)
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("245"))
	riskStyles  = map[domain.RiskLevel]lipgloss.Style{
		domain.RiskInfo:     lipgloss.NewStyle().Foreground(lipgloss.Color("245")),
		domain.RiskLow:      lipgloss.NewStyle().Foreground(lipgloss.Color("75")),
		domain.RiskMedium:   lipgloss.NewStyle().Foreground(lipgloss.Color("214")),
		domain.RiskHigh:     lipgloss.NewStyle().Foreground(lipgloss.Color("203")),
		domain.RiskCritical: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")),
	}
	statusIcon = map[domain.ScanStatus]string{
		domain.StatusSafe:    "✓",
		domain.StatusNew:     "⚠",
		domain.StatusKnown:   "•",
		domain.StatusChanged: "✗",
	}
)

// WriteReport renders a completed scan as the depwatch report: the doki banner with
// live stats, the monitor-style status table, and the running tally footer. It is
// the shared, static (non-animated) view used by the monitor command, the package
// investigation command, and the non-TTY scan path; the interactive scan path uses
// LiveScan for the animated equivalent. When w is not a terminal lipgloss still
// emits ANSI, so callers that pipe should prefer WriteJSON.
func WriteReport(w io.Writer, stats LiveStats, res *domain.ScanResult) {
	var collisions, critical int
	for _, e := range res.Entries {
		if e.Status != domain.StatusSafe {
			collisions++
		}
		if e.Risk == domain.RiskCritical {
			critical++
		}
	}

	writeBanner(w, stats, DOKI[0])

	if len(res.Entries) == 0 {
		fmt.Fprintln(w, dimStyle.Render("  no packages in inventory"))
		return
	}

	fmt.Fprintln(w, dimStyle.Render(fmt.Sprintf("  scan finished · [%d/%d] done", len(res.Entries), len(res.Entries))))
	fmt.Fprintln(w)
	writeTableHeader(w)
	for _, e := range res.Entries {
		if stats.Full {
			writeRow(w, e)
			writeDetails(w, e)
			fmt.Fprintln(w)
			continue
		}
		writeTableRow(w, e)
		if len(e.Signals) > 0 {
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintln(w)
	writeSummary(w, len(res.Entries), collisions, critical, res.Errors)
}

// WriteAlerts renders a list of alerts as a terminal report.
func WriteAlerts(w io.Writer, alerts []domain.Alert) {
	if len(alerts) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no unresolved alerts"))
		return
	}
	fmt.Fprintln(w, titleStyle.Render("depwatch · unresolved alerts"))
	fmt.Fprintln(w)
	for _, a := range alerts {
		fmt.Fprintf(w, "%s %s %s\n", riskStyles[a.Risk].Render(string(a.Risk)), a.PackageName, dimStyle.Render(string(a.Registry)))
	}
}

// WriteHistory renders stored observations for a package, newest first.
func WriteHistory(w io.Writer, name string, entries []domain.ScanEntry) {
	if len(entries) == 0 {
		fmt.Fprintf(w, "%s %s\n", dimStyle.Render("no history for"), name)
		return
	}
	fmt.Fprintf(w, "%s %s\n\n", titleStyle.Render("history"), dimStyle.Render(name))
	for _, e := range entries {
		fmt.Fprintf(w, "%s %s %s %s\n",
			statusIcon[e.Status], e.Registry, riskStyles[e.Risk].Render(string(e.Risk)),
			dimStyle.Render(e.LastSeen.Format("2006-01-02 15:04")))
	}
}

// WriteInventory renders the configured internal package inventory.
func WriteInventory(w io.Writer, org string, pkgs []domain.InternalPackage) {
	fmt.Fprintf(w, "%s %s\n\n", titleStyle.Render("inventory"), dimStyle.Render(org))
	if len(pkgs) == 0 {
		fmt.Fprintln(w, dimStyle.Render("empty"))
		return
	}
	byEco := map[string][]string{}
	for _, p := range pkgs {
		byEco[string(p.Ecosystem)] = append(byEco[string(p.Ecosystem)], p.Name)
	}
	var b strings.Builder
	for eco, names := range byEco {
		b.WriteString(headerStyle.Render(eco + ":\n"))
		for _, n := range names {
			b.WriteString("  ")
			b.WriteString(n)
			b.WriteString("\n")
		}
	}
	fmt.Fprint(w, b.String())
}
