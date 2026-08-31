package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/yourpwnguy/depwatch/internal/cli/output"
)

var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Show the configured internal package inventory",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := configLoad(cmd)
		if err != nil {
			return err
		}
		output.WriteInventory(os.Stdout, cfg.Organization, cfg.InternalPackages())
		return nil
	},
}
