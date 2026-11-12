package config

import (
	"strings"
	"testing"
	"time"

	"github.com/yourpwnguy/depwatch/internal/domain"
)

// validConfig builds the smallest config that should pass validation. Each
// table test mutates one field so the failure points at a single invariant.
func validConfig() *Config {
	return &Config{
		Organization: "acme",
		Ecosystems: map[string][]string{
			"npm":  {"@acme/scheduler"},
			"pypi": {"requests"},
		},
		Registries: map[string]*RegistryConfig{
			"npm":  {Enabled: true},
			"pypi": {Enabled: true},
		},
		Thresholds: ThresholdConfig{Alert: "HIGH", BlockCI: "CRITICAL"},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"valid", func(*Config) {}, ""},
		{"missing organization", func(c *Config) { c.Organization = "" }, "organization is required"},
		{"no ecosystems", func(c *Config) { c.Ecosystems = nil }, "at least one ecosystem"},
		{
			"unknown ecosystem key is rejected",
			func(c *Config) { c.Ecosystems["npmm"] = []string{"typo"} },
			`unknown ecosystem "npmm"`,
		},
		{
			"unknown registry key is rejected",
			func(c *Config) { c.Registries["npmm"] = &RegistryConfig{Enabled: true} },
			`unknown registry "npmm"`,
		},
		{
			"disabled registries only",
			func(c *Config) { c.Registries = map[string]*RegistryConfig{"npm": {Enabled: false}} },
			"at least one registry must be enabled",
		},
		{
			"invalid block_ci threshold",
			func(c *Config) { c.Thresholds.BlockCI = "SEVERE" },
			"valid risk levels",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(c)
			err := c.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	c := &Config{}
	c.ApplyDefaults()

	if c.Database.Path != "depwatch.db" {
		t.Errorf("Database.Path = %q, want depwatch.db", c.Database.Path)
	}
	if c.Scan.Workers != 8 {
		t.Errorf("Scan.Workers = %d, want 8", c.Scan.Workers)
	}
	if c.Scan.Timeout != 10*time.Second {
		t.Errorf("Scan.Timeout = %s, want 10s", c.Scan.Timeout)
	}
	if c.Scan.Retries != 3 {
		t.Errorf("Scan.Retries = %d, want 3", c.Scan.Retries)
	}
	if c.Thresholds.Alert != string(domain.RiskHigh) {
		t.Errorf("Thresholds.Alert = %q, want HIGH", c.Thresholds.Alert)
	}
	if c.Thresholds.BlockCI != string(domain.RiskCritical) {
		t.Errorf("Thresholds.BlockCI = %q, want CRITICAL", c.Thresholds.BlockCI)
	}
}

// TestInternalPackages covers the two filtering rules inventory relies on:
// packages under disabled/unknown registries are skipped, and the result is
// sorted by name so output is stable run to run.
func TestInternalPackages(t *testing.T) {
	c := validConfig()
	c.Ecosystems["npm"] = []string{"b-pkg", "a-pkg"}
	c.Ecosystems["crates"] = []string{"not-scanned"} // registry not enabled

	got := c.InternalPackages()
	want := []domain.InternalPackage{
		{Name: "a-pkg", Ecosystem: domain.EcosystemNpm},
		{Name: "b-pkg", Ecosystem: domain.EcosystemNpm},
		{Name: "requests", Ecosystem: domain.EcosystemPypi},
	}
	if len(got) != len(want) {
		t.Fatalf("InternalPackages() returned %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("InternalPackages()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
