// Package config loads, validates, and normalizes depwatch configuration from YAML.
//
// Configuration sources are searched in order when no explicit path is given:
//   - $DEPWATCH_CONFIG environment variable
//   - ./depwatch.yaml in the current directory
//   - ~/.config/depwatch/config.yaml (XDG-style default)
//
// Security principle: secrets are deliberately absent from the config struct.
// The Slack webhook URL is read from an environment variable at alert-send time
// (see internal/alerting), never stored on disk. This prevents accidental secret
// leakage through version control, config backups, or log files.
//
// Dependency direction: config depends only on domain (for RiskLevel constants and
// Ecosystem/RegistryName types). No other internal package imports config — it is
// assembled by the CLI layer and passed downward into app.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// Config is the top-level configuration, mirroring docs/idea.md §19.
// Every field has a YAML tag matching the depwatch.yaml schema. Zero values
// trigger sensible defaults via applyDefaults() before validation runs.
type Config struct {
	// Organization is the company/team name used for org-specific name detection.
	// A package like "@acme/billing" is flagged more aggressively when Organization
	// is "acme" because it should not exist publicly.
	Organization string `yaml:"organization"`

	// Ecosystems maps ecosystem names (npm, pypi, crates) to lists of internal
	// package names. Only ecosystems with an enabled registry below are scanned —
	// entries under a disabled ecosystem are silently ignored.
	Ecosystems map[string][]string `yaml:"ecosystems"`

	Database DatabaseConfig `yaml:"database"`
	Scan     ScanConfig     `yaml:"scan"`

	// Registries controls which public registries to query. At least one must be
	// enabled. The key is the registry name (npm, pypi, crates).
	Registries map[string]*RegistryConfig `yaml:"registries"`

	Alerts     AlertConfig     `yaml:"alerts"`
	Thresholds ThresholdConfig `yaml:"thresholds"`
}

// DatabaseConfig controls the SQLite persistence layer.
type DatabaseConfig struct {
	// Path is the filesystem path for the SQLite database file. Defaults to
	// "depwatch.db" in the current directory.
	Path string `yaml:"path"`
}

// ScanConfig tunes the scan pipeline's concurrency and network behavior.
type ScanConfig struct {
	// Workers is the number of concurrent (package × registry) lookups. Higher
	// values speed up large inventories but increase load on public registries.
	// Defaults to 8.
	Workers int `yaml:"workers"`

	// Timeout is the per-request HTTP timeout for registry lookups. Defaults to 10s.
	Timeout time.Duration `yaml:"timeout"`

	// Retries is the number of retry attempts on transient HTTP errors (429, 5xx)
	// before marking a lookup as partial. Defaults to 3.
	Retries int `yaml:"retries"`
}

// RegistryConfig enables or disables a single registry by name.
type RegistryConfig struct {
	Enabled bool `yaml:"enabled"`
}

// AlertConfig controls alert delivery sinks.
type AlertConfig struct {
	Slack SlackConfig `yaml:"slack"`
}

// SlackConfig controls Slack webhook notifications. The webhook URL is never
// stored here — it is read from the environment variable named by WebhookEnv
// at alert-send time (see internal/alerting).
type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookEnv string `yaml:"webhook_env"`
}

// ThresholdsConfig defines risk levels that trigger alerts and CI failures.
type ThresholdConfig struct {
	// Alert is the minimum RiskLevel that triggers a notification. Defaults to "HIGH".
	Alert string `yaml:"alert"`

	// BlockCI is the minimum RiskLevel that causes `depwatch ci` to exit non-zero.
	// Defaults to "CRITICAL".
	BlockCI string `yaml:"block_ci"`
}

// Load reads configuration from path. When path is empty, it searches default
// locations (see package doc). The loaded config is normalized with defaults and
// validated before returning.
func Load(path string) (*Config, error) {
	if path == "" {
		path = defaultConfigPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// defaultConfigPath resolves the config file path from environment or convention.
func defaultConfigPath() string {
	if p := os.Getenv("DEPWATCH_CONFIG"); p != "" {
		return p
	}
	if _, err := os.Stat("depwatch.yaml"); err == nil {
		return "depwatch.yaml"
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "depwatch", "config.yaml")
	}
	return "depwatch.yaml"
}

// InternalPackages returns the inventory as domain.InternalPackage values,
// including only ecosystems that also have an enabled registry. A typo'd ecosystem
// name (e.g. "npm" not enabled) silently yields no packages for that ecosystem,
// which is the safe-by-default behavior: we never scan a registry the user did
// not explicitly enable.
func (c *Config) InternalPackages() []domain.InternalPackage {
	var out []domain.InternalPackage
	for eco, names := range c.Ecosystems {
		reg, ok := c.Registries[eco]
		if !ok || !reg.Enabled {
			continue
		}
		for _, n := range names {
			out = append(out, domain.InternalPackage{
				Name:      n,
				Ecosystem: domain.Ecosystem(eco),
			})
		}
	}
	return out
}

// EnabledRegistryNames returns the names of all enabled registries. The order
// is non-deterministic (map iteration); callers that need stability should sort.
func (c *Config) EnabledRegistryNames() []domain.RegistryName {
	var out []domain.RegistryName
	for name, reg := range c.Registries {
		if reg != nil && reg.Enabled {
			out = append(out, domain.RegistryName(name))
		}
	}
	return out
}
