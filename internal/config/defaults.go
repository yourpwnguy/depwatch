package config

import (
	"strings"
	"time"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// ApplyDefaults fills any zero-valued optional fields with sane values so callers
// never have to check for zero. Exported so tests and embedded configs can reuse
// the same normalization path as Load. Registry enablement is NOT defaulted — at
// least one must be explicitly enabled by the user.
func (c *Config) ApplyDefaults() { c.applyDefaults() }

// applyDefaults fills zero-valued fields. The rule is: every field that can
// reasonably have a default gets one; registry enablement does not because
// silently enabling a registry the user didn't ask for would be surprising.
func (c *Config) applyDefaults() {
	if c.Database.Path == "" {
		c.Database.Path = "depwatch.db"
	}
	if c.Scan.Workers <= 0 {
		c.Scan.Workers = 8
	}
	if c.Scan.Timeout <= 0 {
		c.Scan.Timeout = 10 * time.Second
	}
	if c.Scan.Retries <= 0 {
		c.Scan.Retries = 3
	}
	if c.Thresholds.Alert == "" {
		c.Thresholds.Alert = string(domain.RiskHigh)
	}
	if c.Thresholds.BlockCI == "" {
		c.Thresholds.BlockCI = string(domain.RiskCritical)
	}
	// Normalize thresholds to uppercase for consistent comparison downstream.
	if c.Thresholds.Alert != "" {
		c.Thresholds.Alert = strings.ToUpper(c.Thresholds.Alert)
	}
	if c.Thresholds.BlockCI != "" {
		c.Thresholds.BlockCI = strings.ToUpper(c.Thresholds.BlockCI)
	}
}
