package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/yourpwnguy/depwatch/internal/cli/output"
	"github.com/yourpwnguy/depwatch/internal/config"
)

var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Show the configured internal package inventory",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		output.WriteInventory(os.Stdout, cfg.Organization, cfg.InternalPackages())
		return nil
	},
}
