package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "bouncerfox-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)

	binaryPath = filepath.Join(tmp, "bouncerfox")
	build := exec.Command("go", "build", "-o", binaryPath, "./")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		panic("build failed: " + string(out))
	}

	os.Exit(m.Run())
}

func runBinary(t *testing.T, args []string, env ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	cmd.Env = append(os.Environ(), env...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run binary: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

func TestSmoke_ScanClean(t *testing.T) {
	_, _, code := runBinary(t, []string{"scan", "testdata/clean-skill"})
	if code != 0 {
		t.Errorf("scan clean-skill: expected exit 0, got %d", code)
	}
}

func TestSmoke_Rules(t *testing.T) {
	stdout, _, code := runBinary(t, []string{"rules"})
	if code != 0 {
		t.Errorf("rules: expected exit 0, got %d", code)
	}
	if !bytes.Contains([]byte(stdout), []byte("SEC_001")) {
		t.Error("rules output should contain SEC_001")
	}
}

func TestSmoke_Init(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(binaryPath, "init")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("init failed: %s", out)
	}
	data, err := os.ReadFile(filepath.Join(dir, ".bouncerfox.yml"))
	if err != nil {
		t.Fatal("init did not create .bouncerfox.yml")
	}
	if !bytes.Contains(data, []byte("profile: recommended")) {
		t.Error("init config should contain 'profile: recommended'")
	}
}

func TestSmoke_Version(t *testing.T) {
	stdout, _, code := runBinary(t, []string{"version"})
	if code != 0 {
		t.Errorf("version: expected exit 0, got %d", code)
	}
	if !bytes.Contains([]byte(stdout), []byte("bouncerfox")) {
		t.Error("version output should contain 'bouncerfox'")
	}
}

func TestSmoke_CompletionBash(t *testing.T) {
	stdout, _, code := runBinary(t, []string{"completion", "bash"})
	if code != 0 {
		t.Errorf("completion bash: expected exit 0, got %d", code)
	}
	if len(stdout) < 100 {
		t.Error("bash completion output seems too short")
	}
}

func TestSmoke_CompletionZsh(t *testing.T) {
	_, _, code := runBinary(t, []string{"completion", "zsh"})
	if code != 0 {
		t.Errorf("completion zsh: expected exit 0, got %d", code)
	}
}

func TestSmoke_CompletionFish(t *testing.T) {
	_, _, code := runBinary(t, []string{"completion", "fish"})
	if code != 0 {
		t.Errorf("completion fish: expected exit 0, got %d", code)
	}
}

func TestScan_BadSkill_ExitCode1(t *testing.T) {
	_, _, code := runBinary(t, []string{"scan", "testdata/bad-skill"})
	if code != 1 {
		t.Errorf("scan bad-skill: expected exit 1, got %d", code)
	}
}

func TestScan_BadSkill_ContainsRuleIDs(t *testing.T) {
	stdout, _, _ := runBinary(t, []string{"scan", "testdata/bad-skill"})
	for _, id := range []string{"SEC_001", "SEC_002"} {
		if !strings.Contains(stdout, id) {
			t.Errorf("scan output should contain %s", id)
		}
	}
}

func TestScan_BadSkill_JSONFormat(t *testing.T) {
	stdout, _, code := runBinary(t, []string{"scan", "testdata/bad-skill", "--format", "json"})
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
	var envelope struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v\nOutput: %s", err, stdout)
	}
	if len(envelope.Findings) == 0 {
		t.Error("expected at least one finding in JSON output")
	}
	for _, f := range envelope.Findings {
		if _, ok := f["rule_id"]; !ok {
			t.Error("JSON finding missing rule_id field")
		}
		if _, ok := f["severity"]; !ok {
			t.Error("JSON finding missing severity field")
		}
	}
}

func TestScan_BadSkill_SARIFFormat(t *testing.T) {
	stdout, _, code := runBinary(t, []string{"scan", "testdata/bad-skill", "--format", "sarif"})
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
	var sarif map[string]any
	if err := json.Unmarshal([]byte(stdout), &sarif); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
	if _, ok := sarif["$schema"]; !ok {
		t.Error("SARIF output missing $schema")
	}
	if _, ok := sarif["runs"]; !ok {
		t.Error("SARIF output missing runs")
	}
}

func TestScan_SeverityFilter(t *testing.T) {
	stdout, _, _ := runBinary(t, []string{"scan", "testdata/bad-skill", "--severity", "critical"})
	if !strings.Contains(stdout, "SEC_001") {
		t.Error("critical severity filter should still show SEC_001 (critical)")
	}
	if strings.Contains(stdout, "QA_003") {
		t.Error("critical severity filter should hide QA_003 (warn)")
	}
}

func TestScan_BadSettings(t *testing.T) {
	_, _, code := runBinary(t, []string{"scan", "testdata/bad-settings"})
	if code != 1 {
		t.Errorf("scan bad-settings: expected exit 1, got %d", code)
	}
}

func TestScan_ConfigOverride_DisablesRule(t *testing.T) {
	stdout, _, _ := runBinary(t, []string{"scan", "testdata/config-override", "--config", "testdata/config-override/.bouncerfox.yml"})
	if strings.Contains(stdout, "SEC_002") {
		t.Error("SEC_002 should be disabled by config override")
	}
}

func TestScan_RuleFloor_CannotDisableSEC001(t *testing.T) {
	stdout, _, code := runBinary(t, []string{"scan", "testdata/floor-test", "--config", "testdata/floor-test/.bouncerfox.yml"})
	if code != 1 {
		t.Errorf("floor-test: expected exit 1 (SEC_001 should fire), got %d", code)
	}
	if !strings.Contains(stdout, "SEC_001") {
		t.Error("SEC_001 should fire despite config trying to disable it (rule floor)")
	}
}
