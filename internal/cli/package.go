package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/yourpwnguy/depwatch/internal/cli/output"
)

var (
	packageFormat string
	packageFull   bool
)

var packageCmd = &cobra.Command{
	Use:   "package [name]",
	Short: "Investigate a single package across all enabled registries",
	Args:  cobra.ExactArgs(1),
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

		res, err := a.Package(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		if packageFormat == "json" {
			return output.WriteJSON(os.Stdout, res)
		}
		st := buildStats(cfg)
		st.Full = packageFull
		output.WriteReport(os.Stdout, st, res)
		return nil
	},
}

func init() {
	packageCmd.Flags().StringVar(&packageFormat, "format", "human", "output format: human | json")
	packageCmd.Flags().BoolVarP(&packageFull, "full", "f", false, "show the full evidence block for every lookup")
}
