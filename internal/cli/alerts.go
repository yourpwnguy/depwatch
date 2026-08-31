package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/yourpwnguy/depwatch/internal/cli/output"
)

var alertsFormat string

var alertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "List unresolved alerts",
	RunE: func(cmd *cobra.Command, args []string) error {
		a, err := buildApp(cmd)
		if err != nil {
			return err
		}
		defer a.Close()

		alerts, err := a.Alerts(cmd.Context())
		if err != nil {
			return err
		}
		if alertsFormat == "json" {
			return output.WriteAlertsJSON(os.Stdout, alerts)
		}
		output.WriteAlerts(os.Stdout, alerts)
		return nil
	},
}

func init() {
	alertsCmd.Flags().StringVar(&alertsFormat, "format", "human", "output format: human | json")
}
