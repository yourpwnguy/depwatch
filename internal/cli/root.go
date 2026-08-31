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

// configLoad loads configuration from the resolved path. It is a thin wrapper so
// command helpers share one loading path with buildApp.
func configLoad(_ *cobra.Command) (*config.Config, error) { return config.Load(configPath) }

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
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return nil
	}
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "config file path")
}

// buildApp constructs the App from configuration. It is called by every command
// and is the single place where infrastructure (registries, store) is assembled.
// The config path is resolved from the package-level variable set by cobra flags.
func buildApp(_ *cobra.Command) (*app.App, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
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

// buildAppForConfig constructs the App from a config path directly, without
// requiring a cobra.Command. Used by long-running modes (monitor) that build
// a fresh App per cycle without a command context.
func buildAppForConfig(path string) (*app.App, *config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	var regs []registry.Registry
	for _, name := range cfg.EnabledRegistryNames() {
		r, err := registry.New(name, cfg.Scan.Timeout, cfg.Scan.Retries)
		if err != nil {
			return nil, nil, err
		}
		regs = append(regs, r)
	}
	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return nil, nil, err
	}
	return app.New(cfg, regs, store), cfg, nil
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
