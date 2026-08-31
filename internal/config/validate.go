package config

import (
	"fmt"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// Validate enforces the invariants required before a scan can run. These are the
// hard requirements: an organization name, at least one ecosystem listed, at least
// one registry enabled, and valid risk-level strings for thresholds. Returning an
// error here prevents the scan from starting with misconfiguration that would
// produce meaningless results.
func (c *Config) Validate() error {
	if c.Organization == "" {
		return fmt.Errorf("config: organization is required")
	}
	if len(c.Ecosystems) == 0 {
		return fmt.Errorf("config: at least one ecosystem must be listed under 'ecosystems'")
	}
	anyReg := false
	for _, r := range c.Registries {
		if r != nil && r.Enabled {
			anyReg = true
			break
		}
	}
	if !anyReg {
		return fmt.Errorf("config: at least one registry must be enabled under 'registries'")
	}
	if !validRisk(c.Thresholds.Alert) || !validRisk(c.Thresholds.BlockCI) {
		return fmt.Errorf("config: thresholds.alert and thresholds.block_ci must be valid risk levels")
	}
	return nil
}

// validRisk checks that a string is a known RiskLevel. This prevents typos in
// config from silently disabling alerting or CI gating.
func validRisk(s string) bool {
	_, ok := domain.RiskOrder[domain.RiskLevel(s)]
	return ok
}
