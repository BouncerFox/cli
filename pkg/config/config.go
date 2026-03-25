// Package config loads and validates .bouncerfox.yml / .bouncerfox.yaml.
package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/engine"
	"github.com/bouncerfox/cli/pkg/rules"
)

// Profile constants for the scanner configuration.
const (
	ProfileRecommended = "recommended"
	ProfileAllRules    = "all_rules"
)

// RuleConfig holds per-rule overrides from the config file.
type RuleConfig struct {
	// Enabled controls whether the rule runs. nil means use the default (enabled).
	Enabled *bool `yaml:"enabled"`

	// Severity overrides the rule's default severity. nil means use the default.
	Severity *document.FindingSeverity `yaml:"severity"`

	// Params overrides individual rule parameters.
	Params map[string]any `yaml:"params"`
}

// Config is the parsed representation of .bouncerfox.yml.
type Config struct {
	// Profile is "recommended" (default) or "all_rules".
	Profile string `yaml:"profile"`

	// SeverityFloor is the minimum severity level to report. Empty means no floor.
	SeverityFloor document.FindingSeverity `yaml:"severity_floor"`

	// Rules maps rule IDs to their per-rule overrides.
	Rules map[string]RuleConfig `yaml:"rules"`

	// Ignore is a list of gitignore-style path patterns to skip.
	Ignore []string `yaml:"ignore"`
}

// DefaultConfig returns a Config with sensible defaults.
// Profile is "recommended" and all other fields are zero-value.
func DefaultConfig() *Config {
	return &Config{
		Profile: ProfileRecommended,
		Rules:   make(map[string]RuleConfig),
	}
}

// validSeverities is the set of accepted severity strings.
var validSeverities = map[string]document.FindingSeverity{
	"info":     document.SeverityInfo,
	"warn":     document.SeverityWarn,
	"high":     document.SeverityHigh,
	"critical": document.SeverityCritical,
}

// parseSeverity converts a string into a FindingSeverity or returns an error.
func parseSeverity(s string) (document.FindingSeverity, error) {
	if sv, ok := validSeverities[s]; ok {
		return sv, nil
	}
	return "", fmt.Errorf("unknown severity %q: must be one of info, warn, high, critical", s)
}

// knownRuleIDs builds a set of all registered rule IDs.
func knownRuleIDs() map[string]bool {
	m := make(map[string]bool, len(rules.Registry))
	for i := range rules.Registry {
		m[rules.Registry[i].ID] = true
	}
	return m
}

// defaultSeverityForRule returns the default severity of a rule by ID, or ""
// if the rule is not found.
func defaultSeverityForRule(id string) document.FindingSeverity {
	for i := range rules.Registry {
		if rules.Registry[i].ID == id {
			return rules.Registry[i].DefaultSeverity
		}
	}
	return ""
}

// clampSeverity enforces the constraint that CRITICAL rules cannot be
// downgraded below HIGH.
func clampSeverity(ruleID string, sv document.FindingSeverity) document.FindingSeverity {
	defaultSev := defaultSeverityForRule(ruleID)
	if defaultSev == document.SeverityCritical && sv.Level() < document.SeverityHigh.Level() {
		return document.SeverityHigh
	}
	return sv
}

// rawConfig is an intermediate struct used during YAML parsing so we can
// validate string-typed severity fields before converting them.
type rawConfig struct {
	Profile       string                    `yaml:"profile"`
	SeverityFloor string                    `yaml:"severity_floor"`
	Rules         map[string]rawRuleConfig  `yaml:"rules"`
	Ignore        []string                  `yaml:"ignore"`
}

type rawRuleConfig struct {
	Enabled  *bool          `yaml:"enabled"`
	Severity string         `yaml:"severity"`
	Params   map[string]any `yaml:"params"`
}

// LoadConfig searches dir for .bouncerfox.yml or .bouncerfox.yaml, parses it,
// and returns the validated Config. If no file is found, DefaultConfig is
// returned. Validation errors (invalid severity values) are returned as errors.
// Unknown rule IDs are logged as warnings.
func LoadConfig(dir string) (*Config, error) {
	data, err := readConfigFile(dir)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return DefaultConfig(), nil
	}

	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: YAML parse error: %w", err)
	}

	cfg := &Config{
		Profile: raw.Profile,
		Ignore:  raw.Ignore,
		Rules:   make(map[string]RuleConfig, len(raw.Rules)),
	}

	if cfg.Profile == "" {
		cfg.Profile = ProfileRecommended
	}

	// Parse and validate severity_floor.
	if raw.SeverityFloor != "" {
		sv, err := parseSeverity(raw.SeverityFloor)
		if err != nil {
			return nil, fmt.Errorf("config: severity_floor: %w", err)
		}
		cfg.SeverityFloor = sv
	}

	// Parse per-rule configs.
	known := knownRuleIDs()
	for id, rc := range raw.Rules {
		if !known[id] {
			log.Printf("config: warning: unknown rule ID %q (skipping)", id)
		}

		var sv *document.FindingSeverity
		if rc.Severity != "" {
			parsed, err := parseSeverity(rc.Severity)
			if err != nil {
				return nil, fmt.Errorf("config: rule %s severity: %w", id, err)
			}
			// Enforce CRITICAL floor: CRITICAL rules cannot go below HIGH.
			clamped := clampSeverity(id, parsed)
			sv = &clamped
		}

		cfg.Rules[id] = RuleConfig{
			Enabled:  rc.Enabled,
			Severity: sv,
			Params:   rc.Params,
		}
	}

	return cfg, nil
}

// readConfigFile looks for .bouncerfox.yml then .bouncerfox.yaml in dir.
// Returns the file contents, nil if no file found, or an error on read failure.
func readConfigFile(dir string) ([]byte, error) {
	for _, name := range []string{".bouncerfox.yml", ".bouncerfox.yaml"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err == nil {
			return data, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("config: read %s: %w", path, err)
		}
	}
	return nil, nil
}

// ToScanOptions translates the Config into engine.ScanOptions and applies
// per-rule param overrides to rules.RuleParams.
// recommendedDisabled is the set of rules disabled in the "recommended" profile.
var recommendedDisabled = map[string]bool{
	"QA_001":  true,
	"QA_003":  true,
	"QA_008":  true,
	"SEC_006": true,
	"CFG_007": true,
	"CFG_009": true,
}

func (c *Config) ToScanOptions() engine.ScanOptions {
	var disabled []string
	severityOverrides := make(map[string]document.FindingSeverity)

	// Apply profile-based disabling.
	if c.Profile == ProfileRecommended {
		for id := range recommendedDisabled {
			disabled = append(disabled, id)
		}
	}

	for id, rc := range c.Rules {
		if rc.Enabled != nil && !*rc.Enabled {
			disabled = append(disabled, id)
		}
		// Explicit enabled: true overrides profile disabling.
		if rc.Enabled != nil && *rc.Enabled {
			for i, d := range disabled {
				if d == id {
					disabled = append(disabled[:i], disabled[i+1:]...)
					break
				}
			}
		}

		// Apply severity override with floor enforcement.
		if rc.Severity != nil {
			sev := *rc.Severity
			// Enforce severity floor: CRITICAL rules cannot go below HIGH.
			sev = clampSeverity(id, sev)
			severityOverrides[id] = sev
		}

		// Apply per-rule param overrides to the global RuleParams map.
		if len(rc.Params) > 0 {
			if rules.RuleParams[id] == nil {
				rules.RuleParams[id] = make(map[string]any)
			}
			for k, v := range rc.Params {
				rules.RuleParams[id][k] = v
			}
		}
	}

	return engine.ScanOptions{
		DisabledRules:     disabled,
		SeverityFloor:     c.SeverityFloor,
		SeverityOverrides: severityOverrides,
	}
}

// GetRuleParam is a test helper that returns a parameter value from
// rules.RuleParams. It is exported to allow white-box testing from config_test.
func GetRuleParam(ruleID, key string) any {
	if rules.RuleParams[ruleID] == nil {
		return nil
	}
	return rules.RuleParams[ruleID][key]
}

// SetRuleParam is a test helper that sets a parameter value in rules.RuleParams.
// It is exported to allow test teardown / isolation.
func SetRuleParam(ruleID, key string, val any) {
	if rules.RuleParams[ruleID] == nil {
		rules.RuleParams[ruleID] = make(map[string]any)
	}
	rules.RuleParams[ruleID][key] = val
}
