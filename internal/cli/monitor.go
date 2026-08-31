package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourpwnguy/depwatch/internal/app"
	"github.com/yourpwnguy/depwatch/internal/cli/output"
)

// monitorCmd runs scans on an interval until interrupted. Each cycle persists
// observations and raises alerts; the terminal shows a compact summary per cycle.
// Ctrl-C stops it cleanly via the command context cancellation.
//
// Unlike scan, monitor deliberately has no -f flag (would flood cron logs) and
// no live animation (non-interactive by design for background/cron use).
var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Continuously monitor packages on an interval",
	RunE: func(cmd *cobra.Command, args []string) error {
		interval, err := time.ParseDuration(monitorInterval)
		if err != nil {
			return fmt.Errorf("invalid interval %q: %w", monitorInterval, err)
		}
		if interval < 30*time.Second {
			return fmt.Errorf("interval must be at least 30s; got %s", interval)
		}

		ctx := cmd.Context()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			if err := runMonitorCycle(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "monitor cycle error:", err)
			}
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	},
}

var monitorInterval string
var monitorFormat string

// runMonitorCycle builds a fresh App and runs one scan, rendering the result.
// A new App per cycle keeps the store connection lifecycle simple for the
// long-running mode. Uses buildAppForConfig to avoid the cobra.Command hack.
func runMonitorCycle(ctx context.Context) error {
	a, cfg, err := buildAppForConfig(configPath)
	if err != nil {
		return err
	}
	defer a.Close()

	res, err := a.Scan(ctx, app.ScanOptions{})
	if err != nil {
		return err
	}
	if monitorFormat == "json" {
		return output.WriteJSON(os.Stdout, res)
	}
	output.WriteReport(os.Stdout, buildStats(cfg), res)
	return nil
}

func init() {
	monitorCmd.Flags().StringVar(&monitorInterval, "interval", "1h", "scan interval (minimum 30s)")
	monitorCmd.Flags().StringVar(&monitorFormat, "format", "human", "output format: human | json")
}
