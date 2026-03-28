// Package config loads and validates .bouncerfox.yml / .bouncerfox.yaml.
package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/bouncerfox/cli/pkg/configdir"
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

	// FileTypes narrows which file types the rule runs on. Must be a subset of
	// the rule's DefaultFileTypes — any file type not in DefaultFileTypes is
	// silently dropped (intersection semantics).
	FileTypes []string `yaml:"file_types"`
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

	// Target pins the repository identity for connected mode (e.g. "github:org/repo").
	Target string `yaml:"target"`

	// NoFloor disables the minimum rule floor (set via CLI flag, not YAML).
	NoFloor bool `yaml:"-"`
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
	Profile        string                   `yaml:"profile"`
	SeverityFloor  string                   `yaml:"severity_floor"`
	Rules          map[string]rawRuleConfig `yaml:"rules"`
	Ignore         []string                 `yaml:"ignore"`
	Target         string                   `yaml:"target"`
	PlatformPolicy map[string]any           `yaml:"platform_policy"` // parsed and silently discarded
}

type rawRuleConfig struct {
	Enabled   *bool          `yaml:"enabled"`
	Severity  string         `yaml:"severity"`
	Params    map[string]any `yaml:"params"`
	FileTypes []string       `yaml:"file_types"`
}

// parseRawConfig converts a rawConfig into a validated Config.
func parseRawConfig(raw rawConfig) (*Config, error) {
	cfg := &Config{
		Profile: raw.Profile,
		Ignore:  raw.Ignore,
		Target:  raw.Target,
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
			Enabled:   rc.Enabled,
			Severity:  sv,
			Params:    rc.Params,
			FileTypes: rc.FileTypes,
		}
	}

	return cfg, nil
}

// LoadProjectConfig loads config from dir only, with no global merge.
// Used when --config is explicitly provided, and by tests for hermeticity.
func LoadProjectConfig(dir string) (*Config, error) {
	data, err := readConfigFile(dir)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return DefaultConfig(), nil
	}
	return ParseConfigBytes(data)
}

// loadGlobalConfig returns nil if the global config file is missing or unparseable.
func loadGlobalConfig() *Config {
	path := filepath.Join(configdir.Dir(), "config.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	cfg, err := ParseConfigBytes(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not parse %s: %v (skipping global config)\n", path, err)
		return nil
	}
	return cfg
}

// LoadConfig loads project config from dir, merged with global config.
// Global config is loaded from configdir.Dir()/config.yml.
// If global config is missing or malformed, only project config is used.
func LoadConfig(dir string) (*Config, error) {
	global := loadGlobalConfig()
	project, err := LoadProjectConfig(dir)
	if err != nil {
		return nil, err
	}
	return MergeConfigs(global, project), nil
}

// MergeConfigs merges global (base) and project (overlay) configs.
// Scalars: project wins if non-zero. Lists: union (deduplicated by exact string).
// Rules: deep merge at rule ID level; params replaced wholesale.
func MergeConfigs(global, project *Config) *Config {
	if global == nil && project == nil {
		return DefaultConfig()
	}
	if global == nil {
		return project
	}
	if project == nil {
		return global
	}

	merged := &Config{
		Profile:       global.Profile,
		SeverityFloor: global.SeverityFloor,
		Target:        global.Target,
		Ignore:        unionStrings(global.Ignore, project.Ignore),
		Rules:         make(map[string]RuleConfig),
	}

	if project.Profile != "" {
		merged.Profile = project.Profile
	}
	if project.SeverityFloor != "" {
		merged.SeverityFloor = project.SeverityFloor
	}
	if project.Target != "" {
		merged.Target = project.Target
	}
	if merged.Profile == "" {
		merged.Profile = ProfileRecommended
	}

	for id, rc := range global.Rules {
		merged.Rules[id] = rc
	}
	for id, rc := range project.Rules {
		if existing, ok := merged.Rules[id]; ok {
			merged.Rules[id] = mergeRuleConfig(existing, rc)
		} else {
			merged.Rules[id] = rc
		}
	}

	return merged
}

func mergeRuleConfig(base, overlay RuleConfig) RuleConfig {
	result := base
	if overlay.Enabled != nil {
		result.Enabled = overlay.Enabled
	}
	if overlay.Severity != nil {
		result.Severity = overlay.Severity
	}
	if len(overlay.Params) > 0 {
		result.Params = overlay.Params
	}
	if len(overlay.FileTypes) > 0 {
		result.FileTypes = overlay.FileTypes
	}
	return result
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var result []string
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// ParseConfigBytes parses a .bouncerfox.yml config from raw bytes.
// It applies the same validation as LoadConfig. This is used when consuming
// a platform-merged config pulled from the API.
func ParseConfigBytes(data []byte) (*Config, error) {
	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: YAML parse error: %w", err)
	}
	return parseRawConfig(raw)
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

// defaultFileTypesForRule returns the DefaultFileTypes slice for a rule by ID,
// or nil if the rule is not found in the registry.
func defaultFileTypesForRule(id string) []string {
	for i := range rules.Registry {
		if rules.Registry[i].ID == id {
			return rules.Registry[i].DefaultFileTypes
		}
	}
	return nil
}

// intersectFileTypes returns the elements of requested that also appear in
// defaults (order-preserving, intersection semantics).
func intersectFileTypes(requested, defaults []string) []string {
	defaultSet := make(map[string]bool, len(defaults))
	for _, ft := range defaults {
		defaultSet[ft] = true
	}
	var result []string
	for _, ft := range requested {
		if defaultSet[ft] {
			result = append(result, ft)
		}
	}
	return result
}

// ToScanOptions translates the Config into engine.ScanOptions.
// floorRules are the rule IDs that can never be disabled (unless NoFloor is
// set). These protect against the most dangerous classes of finding:
// secrets (SEC_001), destructive commands (SEC_003), invisible unicode (SEC_004).
var floorRules = map[string]bool{
	"SEC_001": true,
	"SEC_003": true,
	"SEC_004": true,
}

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
	ruleParams := rules.DefaultRuleParams()
	var disabled []string
	severityOverrides := make(map[string]document.FindingSeverity)

	// Apply profile-based disabling.
	if c.Profile == ProfileRecommended {
		for id := range recommendedDisabled {
			disabled = append(disabled, id)
		}
	}

	fileTypeOverrides := make(map[string][]string)
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

		if rc.Severity != nil {
			severityOverrides[id] = clampSeverity(id, *rc.Severity)
		}

		if len(rc.Params) > 0 {
			if ruleParams[id] == nil {
				ruleParams[id] = make(map[string]any)
			}
			for k, v := range rc.Params {
				ruleParams[id][k] = v
			}
		}

		if len(rc.FileTypes) > 0 {
			defaults := defaultFileTypesForRule(id)
			narrowed := intersectFileTypes(rc.FileTypes, defaults)
			if len(narrowed) > 0 {
				fileTypeOverrides[id] = narrowed
			}
		}
	}

	if !c.NoFloor {
		var filtered []string
		for _, d := range disabled {
			if floorRules[d] {
				fmt.Fprintf(os.Stderr, "warning: critical rule %s cannot be disabled; enforcing local floor\n", d)
				continue
			}
			filtered = append(filtered, d)
		}
		disabled = filtered

		for id := range fileTypeOverrides {
			if floorRules[id] {
				fmt.Fprintf(os.Stderr, "warning: critical rule %s file_types override ignored; enforcing floor\n", id)
				delete(fileTypeOverrides, id)
			}
		}
	}

	return engine.ScanOptions{
		DisabledRules:     disabled,
		SeverityFloor:     c.SeverityFloor,
		SeverityOverrides: severityOverrides,
		RuleParams:        ruleParams,
		FileTypeOverrides: fileTypeOverrides,
	}
}
