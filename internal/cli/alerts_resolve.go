package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// alertsResolveCmd acknowledges the outstanding alerts for one package. Without
// it, alerts only ever accumulate: the alerts table has had a resolved flag all
// along, but nothing wrote it. Resolution is deliberately manual because only a
// human can decide a collision has been dealt with (claimed, renamed, accepted).
var alertsResolveCmd = &cobra.Command{
	Use:   "resolve [name]",
	Short: "Mark all unresolved alerts for a package as resolved",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		a, _, err := buildApp()
		if err != nil {
			return err
		}
		defer a.Close()

		n, err := a.ResolveAlerts(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		if n == 0 {
			fmt.Fprintf(os.Stdout, "no unresolved alerts for %s\n", args[0])
			return nil
		}
		fmt.Fprintf(os.Stdout, "resolved %d alert(s) for %s\n", n, args[0])
		return nil
	},
}

func init() {
	alertsCmd.AddCommand(alertsResolveCmd)
}
