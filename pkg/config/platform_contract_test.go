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
}
