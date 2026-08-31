package cli

import (
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourpwnguy/depwatch/internal/app"
	"github.com/yourpwnguy/depwatch/internal/cli/output"
	"github.com/yourpwnguy/depwatch/internal/config"
	"github.com/yourpwnguy/depwatch/internal/domain"
)

var (
	scanEcosystem string
	scanFormat    string
	scanFull      bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan all internal packages against public registries",
	RunE: func(cmd *cobra.Command, args []string) error {
		a, err := buildApp(cmd)
		if err != nil {
			return err
		}
		defer a.Close()
		cfg, err := configLoad(cmd)
		if err != nil {
			return err
		}
		ctx := cmd.Context()

		// Machine-readable path: run the scan, emit JSON. No animation.
		if scanFormat == "json" {
			res, err := a.Scan(ctx, app.ScanOptions{Ecosystem: scanEcosystem})
			if err != nil {
				return err
			}
			return output.WriteJSON(os.Stdout, res)
		}

		// Piped/non-TTY path: run the scan, then print the static report.
		// Animations only make sense on an interactive terminal.
		if !isTerminal(os.Stdout) {
			res, err := a.Scan(ctx, app.ScanOptions{Ecosystem: scanEcosystem})
			if err != nil {
				return err
			}
			st := buildStats(cfg)
			st.Full = scanFull
			output.WriteReport(os.Stdout, st, res)
			return nil
		}

		// Interactive path: stream the scan into the normal terminal. Rows commit
		// permanently as lookups land and a single animated status line narrates the
		// current step, so the finished output is the same report monitor prints and
		// stays in scrollback (no alternate screen, no full-screen clears).
		items, stats := buildLive(cfg)
		stats.Full = scanFull
		lr := output.NewLiveScan(os.Stdout, stats, items)
		lr.Start()
		errCh := make(chan error, 1)
		events := make(chan domain.ProgressEvent, 128)
		go func() {
			_, err := a.Scan(ctx, app.ScanOptions{
				Ecosystem: scanEcosystem,
				Progress:  func(e domain.ProgressEvent) { events <- e },
			})
			errCh <- err
			close(events)
		}()

		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case e, ok := <-events:
				if !ok {
					lr.Finish()
					return <-errCh
				}
				lr.Event(e)
				lr.Render()
			case <-ticker.C:
				lr.Tick()
				lr.Render()
			}
		}
	},
}

func init() {
	scanCmd.Flags().StringVar(&scanEcosystem, "ecosystem", "", "restrict scan to one ecosystem (npm, pypi, crates)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "human", "output format: human | json")
	scanCmd.Flags().BoolVarP(&scanFull, "full", "f", false, "show the full evidence block for every lookup")
}

// buildLive derives the pre-known lookup set from configuration. Each internal
// package is paired with the registry of its ecosystem (matching the scanner's
// pairing rule), so the renderer can show "queued" lines before work starts.
func buildLive(cfg *config.Config) ([]output.LiveItem, output.LiveStats) {
	pkgs := cfg.InternalPackages()
	items := make([]output.LiveItem, 0, len(pkgs))
	for _, p := range pkgs {
		items = append(items, output.LiveItem{Pkg: p.Name, Reg: string(p.Ecosystem)})
	}
	return items, buildStats(cfg)
}

// buildStats derives the header metadata (org, enabled registries, inventory size,
// worker count, store path) shared by the live renderer and the static report.
func buildStats(cfg *config.Config) output.LiveStats {
	regs := cfg.EnabledRegistryNames()
	regList := make([]string, 0, len(regs))
	for _, r := range regs {
		regList = append(regList, string(r))
	}
	sort.Strings(regList)
	return output.LiveStats{
		Org:        cfg.Organization,
		Registries: strings.Join(regList, " · "),
		Inventory:  len(cfg.InternalPackages()),
		Workers:    cfg.Scan.Workers,
		Store:      cfg.Database.Path,
		Version:    cliVersion,
	}
}

// isTerminal reports whether f is an interactive terminal, so progress animation
// is suppressed when output is piped.
func isTerminal(f *os.File) bool {
	return termIsTerminal(int(f.Fd()))
}
