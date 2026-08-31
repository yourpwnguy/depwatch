package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// ciCmd runs a scan and exits non-zero when any entry meets the configured
// block_ci threshold. It is designed for CI pipelines: stdout carries a short
// summary, and the process exit code signals gate failure.
var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "Run a scan for CI and exit non-zero on policy breach",
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

		res, err := a.CI(cmd.Context())
		if err != nil {
			return err
		}

		breached := false
		for _, e := range res.Entries {
			if e.Status != domain.StatusSafe &&
				domain.RiskAtLeast(e.Risk, domain.RiskLevel(cfg.Thresholds.BlockCI)) {
				breached = true
				fmt.Fprintf(os.Stderr, "POLICY BREACH: %s (%s) risk=%s\n", e.PackageName, e.Registry, e.Risk)
			}
		}

		if res.Partial {
			fmt.Fprintln(os.Stderr, "WARNING: scan incomplete due to registry errors")
		}

		if breached {
			os.Exit(2)
		}
		return nil
	},
}
