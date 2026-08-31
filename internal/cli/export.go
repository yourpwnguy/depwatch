package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/yourpwnguy/depwatch/internal/app"
	"github.com/yourpwnguy/depwatch/internal/cli/output"
)

// exportCmd runs a scan and writes the raw JSON result to a file. The output is
// identical to `scan --format json` but intended for archival/CI artifact upload.
var exportCmd = &cobra.Command{
	Use:   "export [file]",
	Short: "Export a full scan as JSON to a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		a, err := buildApp(cmd)
		if err != nil {
			return err
		}
		defer a.Close()

		res, err := a.Scan(cmd.Context(), app.ScanOptions{})
		if err != nil {
			return err
		}
		f, err := os.Create(args[0])
		if err != nil {
			return err
		}
		defer f.Close()
		return output.WriteJSON(f, res)
	},
}
