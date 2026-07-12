package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bouncerfox/cli/pkg/config"
)

func TestPhase1ConfigPullResponse_ParsesCanonicalFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "contracts", "phase1", "config-pull-response.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	cfg, rulesVersion, err := config.ParsePlatformConfig(data)
	if err != nil {
		t.Fatalf("ParsePlatformConfig: %v", err)
	}
	if cfg.Profile != "recommended" {
		t.Fatalf("expected recommended profile, got %q", cfg.Profile)
	}
	if rulesVersion != "phase1-contract" {
		t.Fatalf("expected phase1-contract rules_version, got %q", rulesVersion)
	}
	qa005, ok := cfg.Rules["QA_005"]
	if !ok {
		t.Fatal("expected disabled rule QA_005 to be present")
	}
	if qa005.Enabled == nil || *qa005.Enabled {
		t.Fatalf("expected QA_005 to be disabled, got %+v", qa005)
	}
	if len(cfg.CustomRules) != 1 {
		t.Fatalf("expected 1 custom rule, got %d", len(cfg.CustomRules))
	}
	rule := cfg.CustomRules[0]
	if rule.RuleID != "CUSTOM_001" {
		t.Fatalf("expected rule_id CUSTOM_001, got %q", rule.RuleID)
	}
	if rule.Severity != "high" {
		t.Fatalf("expected severity high, got %q", rule.Severity)
	}
	if rule.Schema != 1 {
		t.Fatalf("expected schema_version 1, got %d", rule.Schema)
	}
	if len(rule.FileTypes) != 1 || rule.FileTypes[0] != "skill_md" {
		t.Fatalf("expected file_types [skill_md], got %v", rule.FileTypes)
	}
	if got := rule.MatchConfig["type"]; got != "regex" {
		t.Fatalf("expected match_config.type regex, got %#v", got)
	}
	if got := rule.MatchConfig["pattern"]; got != `eval\(` {
		t.Fatalf("expected match_config.pattern eval\\(, got %#v", got)
	}
}
