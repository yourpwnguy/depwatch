package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/yourpwnguy/depwatch/internal/cli/output"
)

var historyCmd = &cobra.Command{
	Use:   "history [name]",
	Short: "Show stored scan history for a package",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		a, err := buildApp(cmd)
		if err != nil {
			return err
		}
		defer a.Close()

		entries, err := a.History(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		output.WriteHistory(os.Stdout, args[0], entries)
		return nil
	},
}
