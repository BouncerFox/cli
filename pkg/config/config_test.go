package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bouncerfox/cli/pkg/config"
	"github.com/bouncerfox/cli/pkg/document"
)

// writeConfig writes content to .bouncerfox.yml in a temp dir and returns the dir.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".bouncerfox.yml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestDefaultConfig verifies the defaults when no config file is present.
func TestDefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.Profile != "recommended" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "recommended")
	}
	if cfg.SeverityFloor != "" {
		t.Errorf("SeverityFloor = %q, want empty", cfg.SeverityFloor)
	}
	if cfg.Rules == nil {
		t.Error("Rules map must not be nil")
	}
	if len(cfg.Ignore) != 0 {
		t.Errorf("Ignore should be empty, got %v", cfg.Ignore)
	}
}

// TestLoadConfig_NoFile returns DefaultConfig when no file is found.
func TestLoadConfig_NoFile(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Profile != "recommended" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "recommended")
	}
}

// TestLoadConfig_YAMLExtension verifies .bouncerfox.yaml is also found.
func TestLoadConfig_YAMLExtension(t *testing.T) {
	dir := t.TempDir()
	content := "profile: all_rules\n"
	if err := os.WriteFile(filepath.Join(dir, ".bouncerfox.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Profile != "all_rules" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "all_rules")
	}
}

// TestLoadConfig_Profile parses the profile field.
func TestLoadConfig_Profile(t *testing.T) {
	dir := writeConfig(t, "profile: all_rules\n")
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Profile != "all_rules" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "all_rules")
	}
}

// TestLoadConfig_SeverityFloor parses the severity_floor field.
func TestLoadConfig_SeverityFloor(t *testing.T) {
	dir := writeConfig(t, "severity_floor: warn\n")
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SeverityFloor != document.SeverityWarn {
		t.Errorf("SeverityFloor = %q, want %q", cfg.SeverityFloor, document.SeverityWarn)
	}
}

// TestLoadConfig_InvalidSeverityFloor returns an error for unknown severities.
func TestLoadConfig_InvalidSeverityFloor(t *testing.T) {
	dir := writeConfig(t, "severity_floor: extreme\n")
	_, err := config.LoadConfig(dir)
	if err == nil {
		t.Error("expected error for invalid severity_floor, got nil")
	}
}

// TestLoadConfig_RuleEnabled parses per-rule enabled field.
func TestLoadConfig_RuleEnabled(t *testing.T) {
	yaml := `
rules:
  SEC_001:
    enabled: false
`
	dir := writeConfig(t, yaml)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rc, ok := cfg.Rules["SEC_001"]
	if !ok {
		t.Fatal("expected rule config for SEC_001")
	}
	if rc.Enabled == nil {
		t.Fatal("Enabled should not be nil")
	}
	if *rc.Enabled {
		t.Error("Enabled = true, want false")
	}
}

// TestLoadConfig_RuleSeverityOverride parses per-rule severity field.
func TestLoadConfig_RuleSeverityOverride(t *testing.T) {
	yaml := `
rules:
  SEC_006:
    severity: high
`
	dir := writeConfig(t, yaml)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rc, ok := cfg.Rules["SEC_006"]
	if !ok {
		t.Fatal("expected rule config for SEC_006")
	}
	if rc.Severity == nil {
		t.Fatal("Severity should not be nil")
	}
	if *rc.Severity != document.SeverityHigh {
		t.Errorf("Severity = %q, want %q", *rc.Severity, document.SeverityHigh)
	}
}

// TestLoadConfig_RuleInvalidSeverity returns an error for unknown per-rule severity.
func TestLoadConfig_RuleInvalidSeverity(t *testing.T) {
	yaml := `
rules:
  SEC_006:
    severity: badvalue
`
	dir := writeConfig(t, yaml)
	_, err := config.LoadConfig(dir)
	if err == nil {
		t.Error("expected error for invalid rule severity, got nil")
	}
}

// TestLoadConfig_RuleParams parses per-rule params.
func TestLoadConfig_RuleParams(t *testing.T) {
	yaml := `
rules:
  SEC_006:
    params:
      min_base64_length: 50
`
	dir := writeConfig(t, yaml)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rc, ok := cfg.Rules["SEC_006"]
	if !ok {
		t.Fatal("expected rule config for SEC_006")
	}
	v, ok := rc.Params["min_base64_length"]
	if !ok {
		t.Fatal("expected param min_base64_length")
	}
	// YAML integers decode as int
	if v.(int) != 50 {
		t.Errorf("min_base64_length = %v (%T), want 50 (int)", v, v)
	}
}

// TestLoadConfig_IgnorePatterns parses the ignore list.
func TestLoadConfig_IgnorePatterns(t *testing.T) {
	yaml := `
ignore:
  - "vendor/**"
  - "*.generated.go"
`
	dir := writeConfig(t, yaml)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Ignore) != 2 {
		t.Fatalf("Ignore len = %d, want 2", len(cfg.Ignore))
	}
	if cfg.Ignore[0] != "vendor/**" {
		t.Errorf("Ignore[0] = %q, want %q", cfg.Ignore[0], "vendor/**")
	}
	if cfg.Ignore[1] != "*.generated.go" {
		t.Errorf("Ignore[1] = %q, want %q", cfg.Ignore[1], "*.generated.go")
	}
}

// TestLoadConfig_FullExample tests a complete realistic config file.
func TestLoadConfig_FullExample(t *testing.T) {
	yaml := `
profile: recommended
severity_floor: warn
rules:
  SEC_001:
    enabled: false
  SEC_006:
    severity: high
    params:
      min_base64_length: 50
  QA_003:
    params:
      min_description_length: 30
ignore:
  - "vendor/**"
  - "*.generated.go"
`
	dir := writeConfig(t, yaml)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Profile != "recommended" {
		t.Errorf("Profile = %q", cfg.Profile)
	}
	if cfg.SeverityFloor != document.SeverityWarn {
		t.Errorf("SeverityFloor = %q", cfg.SeverityFloor)
	}

	// SEC_001 disabled
	sec001, ok := cfg.Rules["SEC_001"]
	if !ok || sec001.Enabled == nil || *sec001.Enabled {
		t.Error("SEC_001 should be disabled")
	}

	// SEC_006 severity override + param
	sec006, ok := cfg.Rules["SEC_006"]
	if !ok {
		t.Fatal("expected SEC_006 rule config")
	}
	if sec006.Severity == nil || *sec006.Severity != document.SeverityHigh {
		t.Error("SEC_006 severity should be high")
	}
	if sec006.Params["min_base64_length"].(int) != 50 {
		t.Error("SEC_006 min_base64_length should be 50")
	}

	// QA_003 params
	qa003, ok := cfg.Rules["QA_003"]
	if !ok {
		t.Fatal("expected QA_003 rule config")
	}
	if qa003.Params["min_description_length"].(int) != 30 {
		t.Error("QA_003 min_description_length should be 30")
	}

	if len(cfg.Ignore) != 2 {
		t.Errorf("Ignore len = %d, want 2", len(cfg.Ignore))
	}
}

// TestToScanOptions_SeverityFloor verifies SeverityFloor flows through to ScanOptions.
func TestToScanOptions_SeverityFloor(t *testing.T) {
	yaml := "severity_floor: high\n"
	dir := writeConfig(t, yaml)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := cfg.ToScanOptions()
	if opts.SeverityFloor != document.SeverityHigh {
		t.Errorf("SeverityFloor = %q, want %q", opts.SeverityFloor, document.SeverityHigh)
	}
}

// TestToScanOptions_DisabledRule verifies a disabled rule appears in DisabledRules.
// Uses SEC_006 (non-floor rule) to avoid the minimum rule floor enforcement.
func TestToScanOptions_DisabledRule(t *testing.T) {
	yaml := `
rules:
  SEC_006:
    enabled: false
`
	dir := writeConfig(t, yaml)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := cfg.ToScanOptions()

	found := false
	for _, id := range opts.DisabledRules {
		if id == "SEC_006" {
			found = true
		}
	}
	if !found {
		t.Errorf("SEC_006 should be in DisabledRules, got: %v", opts.DisabledRules)
	}
}

// TestToScanOptions_EnabledRule verifies an explicitly enabled rule does not
// appear in DisabledRules (a rule with enabled:true should never be disabled).
func TestToScanOptions_EnabledRule(t *testing.T) {
	yaml := `
rules:
  SEC_001:
    enabled: true
`
	dir := writeConfig(t, yaml)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	opts := cfg.ToScanOptions()

	for _, id := range opts.DisabledRules {
		if id == "SEC_001" {
			t.Error("SEC_001 should not be in DisabledRules when enabled:true")
		}
	}
}

// TestToScanOptions_ParamsApplied verifies per-rule params are merged into
// rules.RuleParams when ToScanOptions is called.
func TestToScanOptions_ParamsApplied(t *testing.T) {
	yaml := `
rules:
  SEC_006:
    params:
      min_base64_length: 99
`
	dir := writeConfig(t, yaml)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Capture original value.
	origVal := getRuleParam(t, "SEC_006", "min_base64_length")

	cfg.ToScanOptions()

	// After ToScanOptions the global RuleParams should reflect the override.
	newVal := getRuleParam(t, "SEC_006", "min_base64_length")
	if newVal != 99 {
		t.Errorf("min_base64_length = %v, want 99", newVal)
	}

	// Restore for test isolation.
	setRuleParam(t, "SEC_006", "min_base64_length", origVal)
}

// TestSeverityFloorCriticalFloor verifies that CRITICAL rules cannot be
// downgraded below HIGH via per-rule severity override.
func TestSeverityFloorCriticalFloor(t *testing.T) {
	yaml := `
rules:
  SEC_001:
    severity: info
`
	dir := writeConfig(t, yaml)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rc := cfg.Rules["SEC_001"]
	// The severity should have been clamped to high.
	if rc.Severity == nil {
		t.Fatal("Severity should not be nil after clamping")
	}
	if *rc.Severity != document.SeverityHigh {
		t.Errorf("CRITICAL rule severity clamped to %q, want %q", *rc.Severity, document.SeverityHigh)
	}
}

func TestLoadConfig_UnknownFields(t *testing.T) {
	content := "profile: recommended\nunknown_field: value\nextra_stuff:\n  nested: true\n"
	dir := writeConfig(t, content)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Profile != "recommended" {
		t.Errorf("expected profile 'recommended', got %q", cfg.Profile)
	}
}

func TestLoadConfig_EmptyFile(t *testing.T) {
	dir := writeConfig(t, "")
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Profile != "recommended" {
		t.Errorf("expected default profile, got %q", cfg.Profile)
	}
}

func TestConfig_TargetField(t *testing.T) {
	dir := writeConfig(t, "target: github:test/repo\nprofile: recommended\n")
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target != "github:test/repo" {
		t.Errorf("expected target, got %q", cfg.Target)
	}
}

func TestConfig_PlatformPolicyStripped(t *testing.T) {
	dir := writeConfig(t, "profile: recommended\nplatform_policy:\n  block_threshold: critical\n")
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != "recommended" {
		t.Errorf("expected recommended, got %q", cfg.Profile)
	}
}

func TestConfig_MinimumRuleFloor(t *testing.T) {
	dir := writeConfig(t, "profile: all_rules\nrules:\n  SEC_001:\n    enabled: false\n  SEC_003:\n    enabled: false\n  SEC_004:\n    enabled: false\n")
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	opts := cfg.ToScanOptions()
	disabled := make(map[string]bool)
	for _, d := range opts.DisabledRules {
		disabled[d] = true
	}
	for _, critical := range []string{"SEC_001", "SEC_003", "SEC_004"} {
		if disabled[critical] {
			t.Errorf("critical rule %s should not be disableable", critical)
		}
	}
}

func TestConfig_NoFloorBypasses(t *testing.T) {
	dir := writeConfig(t, "profile: all_rules\nrules:\n  SEC_001:\n    enabled: false\n")
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.NoFloor = true
	opts := cfg.ToScanOptions()
	disabled := make(map[string]bool)
	for _, d := range opts.DisabledRules {
		disabled[d] = true
	}
	if !disabled["SEC_001"] {
		t.Error("SEC_001 should be disableable when NoFloor=true")
	}
}

func TestParseConfigBytes(t *testing.T) {
	data := []byte("profile: all_rules\ntarget: github:test/repo\n")
	cfg, err := config.ParseConfigBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != "all_rules" {
		t.Errorf("expected all_rules, got %q", cfg.Profile)
	}
	if cfg.Target != "github:test/repo" {
		t.Errorf("expected target, got %q", cfg.Target)
	}
}

// helpers to access rules.RuleParams without importing rules in the test file.

func getRuleParam(t *testing.T, ruleID, key string) any {
	t.Helper()
	return config.GetRuleParam(ruleID, key)
}

func setRuleParam(t *testing.T, ruleID, key string, val any) {
	t.Helper()
	config.SetRuleParam(ruleID, key, val)
}
