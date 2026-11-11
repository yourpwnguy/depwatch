// Package cli wires the cobra command tree to the application and renders output.
// Commands parse flags, call app methods, and hand results to the output package.
// No security logic lives here — this is purely presentation and orchestration.
//
// Dependency direction: cli → app → domain, cli → output → domain. The cli package
// is the only place where infrastructure is assembled (registries, store, config)
// and injected into the app layer.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/yourpwnguy/depwatch/internal/app"
	"github.com/yourpwnguy/depwatch/internal/config"
	"github.com/yourpwnguy/depwatch/internal/registry"
	"github.com/yourpwnguy/depwatch/internal/storage"
)

// termIsTerminal reports whether the given file descriptor is an interactive
// terminal. Used to suppress progress animation when output is piped.
func termIsTerminal(fd int) bool { return term.IsTerminal(fd) }

// rootCmd is the base command. It holds the --config flag and provides the
// entrypoint for all subcommands. The config path is resolved once and shared
// across the command tree via the package-level configPath variable.
var rootCmd = &cobra.Command{
	Use:     "depwatch",
	Short:   "Dependency confusion monitor",
	Long:    "depwatch detects public packages that collide with your internal dependencies and assesses the supply-chain risk.",
	Version: "0.1.0",
}

var configPath string

// cliVersion is the build-time version string, set by Run().
var cliVersion string

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "config file path")
}

// buildApp loads configuration and assembles the App. It is the single entry
// point commands use, and it returns the loaded config too so callers do not
// have to load the file a second time just to read a threshold or build the
// banner stats. One read means one source of truth per command run.
func buildApp() (*app.App, *config.Config, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	a, err := newApp(cfg)
	if err != nil {
		return nil, nil, err
	}
	return a, cfg, nil
}

// newApp wires registries and storage for an already-loaded config. It is split
// from buildApp so long-running modes (monitor) can rebuild the App for a new
// scan cycle without re-reading the config file every time.
func newApp(cfg *config.Config) (*app.App, error) {
	var regs []registry.Registry
	for _, name := range cfg.EnabledRegistryNames() {
		r, err := registry.New(name, cfg.Scan.Timeout, cfg.Scan.Retries)
		if err != nil {
			return nil, err
		}
		regs = append(regs, r)
	}
	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return nil, err
	}
	return app.New(cfg, regs, store), nil
}

// Run executes the CLI. It is the entry point called from main.
// The version string is stamped at build time via -ldflags.
func Run(version string) {
	cliVersion = version
	rootCmd.Version = version
	rootCmd.AddCommand(
		scanCmd, packageCmd, historyCmd, alertsCmd,
		inventoryCmd, exportCmd, monitorCmd, ciCmd,
	)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
