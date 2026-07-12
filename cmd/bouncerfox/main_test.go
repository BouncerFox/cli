package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "bouncerfox-test-*")
	if err != nil {
		panic(err)
	}

	binaryName := "bouncerfox"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath = filepath.Join(tmp, binaryName)
	build := exec.CommandContext(
		context.Background(),
		"go", "build",
		"-tags", "enable_platform",
		"-ldflags", "-X main.version=test-version",
		"-o", binaryPath,
		"./",
	)
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		panic("build failed: " + string(out))
	}

	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

func runBinary(t *testing.T, args []string, env ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), binaryPath, args...)
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

type cliJSONFinding struct {
	RuleID      string `json:"rule_id"`
	Fingerprint string `json:"fingerprint"`
	Evidence    struct {
		File string `json:"file"`
	} `json:"evidence"`
}

func decodeCLIJSONFindings(t *testing.T, raw string) []cliJSONFinding {
	t.Helper()
	var output struct {
		Findings []cliJSONFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(raw), &output); err != nil {
		t.Fatalf("decoding scan output: %v\n%s", err, raw)
	}
	return output.Findings
}

func findingForRule(t *testing.T, findings []cliJSONFinding, ruleID string) cliJSONFinding {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return finding
		}
	}
	t.Fatalf("finding for %s not present: %+v", ruleID, findings)
	return cliJSONFinding{}
}

func TestSmoke_ScanClean(t *testing.T) {
	_, _, code := runBinary(t, []string{"scan", "testdata/clean-skill"})
	if code != 0 {
		t.Errorf("scan clean-skill: expected exit 0, got %d", code)
	}
}

func TestScan_FingerprintsStableAcrossCheckoutRoots(t *testing.T) {
	const relativeSkillPath = ".claude/skills/sample/SKILL.md"
	const skill = `---
name: sample
description: A documented skill used to verify checkout-independent fingerprints.
---
api_key: 0123456789abcdef0123456789abcdef
`

	scanCheckout := func(t *testing.T) cliJSONFinding {
		t.Helper()
		root := t.TempDir()
		skillPath := filepath.Join(root, filepath.FromSlash(relativeSkillPath))
		if err := os.MkdirAll(filepath.Dir(skillPath), 0o700); err != nil {
			t.Fatalf("creating skill directory: %v", err)
		}
		if err := os.WriteFile(skillPath, []byte(skill), 0o600); err != nil {
			t.Fatalf("writing skill: %v", err)
		}

		stdout, stderr, code := runBinary(t, []string{"scan", root, "--format", "json"})
		if code != 1 {
			t.Fatalf("expected secret finding exit 1, got %d: %s", code, stderr)
		}
		return findingForRule(t, decodeCLIJSONFindings(t, stdout), "SEC_001")
	}

	first := scanCheckout(t)
	second := scanCheckout(t)
	if first.Evidence.File != relativeSkillPath {
		t.Errorf("evidence file = %q, want %q", first.Evidence.File, relativeSkillPath)
	}
	if second.Evidence.File != relativeSkillPath {
		t.Errorf("second evidence file = %q, want %q", second.Evidence.File, relativeSkillPath)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Errorf("fingerprints differ across checkout roots: %q != %q", first.Fingerprint, second.Fingerprint)
	}
}

func TestScan_MultipleRootsNamespaceIdenticalFindings(t *testing.T) {
	workspace := t.TempDir()
	const relativeSkillPath = ".claude/skills/sample/SKILL.md"
	const skill = "---\nname: sample\ndescription: A documented multi-root fingerprint regression skill.\n---\napi_key: 0123456789abcdef0123456789abcdef\n"

	roots := []string{filepath.Join(workspace, "dir-a"), filepath.Join(workspace, "dir-b")}
	for _, root := range roots {
		skillPath := filepath.Join(root, filepath.FromSlash(relativeSkillPath))
		if err := os.MkdirAll(filepath.Dir(skillPath), 0o700); err != nil {
			t.Fatalf("creating skill directory: %v", err)
		}
		if err := os.WriteFile(skillPath, []byte(skill), 0o600); err != nil {
			t.Fatalf("writing skill: %v", err)
		}
	}

	stdout, stderr, code := runBinary(t, []string{"scan", roots[0], roots[1], "--format", "json"})
	if code != 1 {
		t.Fatalf("expected findings exit 1, got %d: %s", code, stderr)
	}

	paths := make(map[string]bool)
	fingerprints := make(map[string]bool)
	for _, finding := range decodeCLIJSONFindings(t, stdout) {
		if finding.RuleID != "SEC_001" {
			continue
		}
		paths[finding.Evidence.File] = true
		fingerprints[finding.Fingerprint] = true
	}
	wantPaths := []string{
		"dir-a/" + relativeSkillPath,
		"dir-b/" + relativeSkillPath,
	}
	for _, want := range wantPaths {
		if !paths[want] {
			t.Errorf("missing evidence path %q; got %v", want, paths)
		}
	}
	if len(paths) != 2 {
		t.Errorf("SEC_001 evidence paths = %v, want two distinct paths", paths)
	}
	if len(fingerprints) != 2 {
		t.Errorf("SEC_001 fingerprints = %v, want two distinct fingerprints", fingerprints)
	}
}

func TestScan_SingleFileRootUsesBasenameAndStructuralRoute(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatalf("creating settings directory: %v", err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"allowedTools":["Bash"]}`), 0o600); err != nil {
		t.Fatalf("writing settings: %v", err)
	}

	stdout, stderr, code := runBinary(t, []string{"scan", settingsPath, "--format", "json"})
	if code != 1 {
		t.Fatalf("expected settings finding exit 1, got %d: %s", code, stderr)
	}
	finding := findingForRule(t, decodeCLIJSONFindings(t, stdout), "CFG_001")
	if finding.Evidence.File != "settings.json" {
		t.Errorf("evidence file = %q, want settings.json", finding.Evidence.File)
	}
}

func TestScan_DirectSkillFilePreservesQA002StructuralContext(t *testing.T) {
	skillPath := filepath.Join(t.TempDir(), ".claude", "skills", "expected-name", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(skillPath), 0o700); err != nil {
		t.Fatalf("creating skill directory: %v", err)
	}
	content := "---\nname: wrong-name\ndescription: A documented skill with a deliberately mismatched directory name.\n---\nBody\n"
	if err := os.WriteFile(skillPath, []byte(content), 0o600); err != nil {
		t.Fatalf("writing skill: %v", err)
	}

	stdout, stderr, code := runBinary(t, []string{"scan", skillPath, "--format", "json"})
	if code != 1 {
		t.Fatalf("expected QA_002 finding exit 1, got %d: %s", code, stderr)
	}
	finding := findingForRule(t, decodeCLIJSONFindings(t, stdout), "QA_002")
	if finding.Evidence.File != "SKILL.md" {
		t.Errorf("evidence file = %q, want SKILL.md", finding.Evidence.File)
	}
}

func TestScan_SymlinkedDirectoryRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlinks require privileges on Windows")
	}

	workspace := t.TempDir()
	realRoot := filepath.Join(workspace, "real-checkout")
	skillPath := filepath.Join(realRoot, ".claude", "skills", "sample", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(skillPath), 0o700); err != nil {
		t.Fatalf("creating skill directory: %v", err)
	}
	if err := os.WriteFile(skillPath, []byte("---\nname: sample\ndescription: A documented symlink-root regression skill.\n---\napi_key: 0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("writing skill: %v", err)
	}

	linkedRoot := filepath.Join(workspace, "linked-checkout")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Skipf("creating directory symlink: %v", err)
	}

	stdout, stderr, code := runBinary(t, []string{"scan", linkedRoot, "--format", "json"})
	if code != 1 {
		t.Fatalf("expected symlinked-root finding exit 1, got %d: %s", code, stderr)
	}
	finding := findingForRule(t, decodeCLIJSONFindings(t, stdout), "SEC_001")
	if finding.Evidence.File != ".claude/skills/sample/SKILL.md" {
		t.Errorf("evidence file = %q, want relative path", finding.Evidence.File)
	}
}

func TestScan_RejectsChildSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file symlinks require privileges on Windows")
	}

	workspace := t.TempDir()
	root := filepath.Join(workspace, "scan-root")
	outside := filepath.Join(workspace, "outside")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("creating scan root: %v", err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatalf("creating outside directory: %v", err)
	}
	outsideSkill := filepath.Join(outside, "SKILL.md")
	if err := os.WriteFile(outsideSkill, []byte("---\nname: escaped\ndescription: This file must remain outside the scan root.\n---\napi_key: 0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("writing outside skill: %v", err)
	}
	linkedSkill := filepath.Join(root, "SKILL.md")
	if err := os.Symlink(outsideSkill, linkedSkill); err != nil {
		t.Skipf("creating file symlink: %v", err)
	}

	stdout, stderr, code := runBinary(t, []string{"scan", root, "--format", "json"})
	if code != 0 {
		t.Fatalf("expected escaped child to be skipped with exit 0, got %d: %s", code, stderr)
	}
	if findings := decodeCLIJSONFindings(t, stdout); len(findings) != 0 {
		t.Fatalf("escaped child produced findings: %+v", findings)
	}
	if !strings.Contains(stderr, "resolves outside scan root") {
		t.Errorf("stderr missing escape warning: %s", stderr)
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
	cmd := exec.CommandContext(context.Background(), binaryPath, "init")
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
	runs, ok := sarif["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatal("SARIF output has no runs")
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatal("SARIF run has unexpected shape")
	}
	tool, ok := run["tool"].(map[string]any)
	if !ok {
		t.Fatal("SARIF run is missing tool metadata")
	}
	driver, ok := tool["driver"].(map[string]any)
	if !ok {
		t.Fatal("SARIF tool is missing driver metadata")
	}
	if got := driver["version"]; got != "test-version" {
		t.Errorf("SARIF driver version = %v, want test-version", got)
	}
}

func TestScan_RejectsInvalidValues(t *testing.T) {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "custom-scan-config.yml")
	if err := os.WriteFile(configPath, []byte("profile: strict\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "output format",
			args:    []string{"scan", "testdata/clean-skill", "--format", "xml"},
			wantErr: `unknown output format "xml": must be one of table, json, sarif`,
		},
		{
			name:    "profile",
			args:    []string{"scan", "testdata/clean-skill", "--config", configPath},
			wantErr: `unknown profile "strict": must be one of recommended, all_rules`,
		},
		{
			name:    "offline behavior",
			args:    []string{"scan", "testdata/clean-skill", "--offline-behavior", "ignore"},
			wantErr: `unknown offline behavior "ignore": must be one of warn, fail-closed`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runBinary(t, tt.args)
			if code != 2 {
				t.Errorf("expected exit 2, got %d", code)
			}
			if stdout != "" {
				t.Errorf("expected no scan output, got %q", stdout)
			}
			if !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("stderr should contain %q, got %q", tt.wantErr, stderr)
			}
		})
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
	if strings.Contains(stdout, "QA_002") {
		t.Error("QA_002 should be disabled by config override")
	}
}

func TestScan_ExactConfigExecutesLocalCustomRule(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temporary scan root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".bouncerfox.yml"), []byte("ignore:\n  - SKILL.md\n"), 0o600); err != nil {
		t.Fatalf("writing conventional config: %v", err)
	}
	skill := []byte(`---
name: local-custom-rule-test
description: A documented skill used to verify local custom rule execution.
---
BOUNCERFOX_CUSTOM_SENTINEL
`)
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), skill, 0o600); err != nil {
		t.Fatalf("writing governed file: %v", err)
	}
	configPath := filepath.Join(root, "strict-policy.yml")
	customConfig := []byte(`custom_rules:
  - id: CUSTOM_900
    name: Detect local sentinel
    severity: high
    file_types: [skill_md]
    match:
      type: content_contains
      value: BOUNCERFOX_CUSTOM_SENTINEL
    remediation: Remove the sentinel
`)
	if err := os.WriteFile(configPath, customConfig, 0o600); err != nil {
		t.Fatalf("writing exact custom config: %v", err)
	}

	stdout, stderr, code := runBinary(t, []string{"scan", root, "--config", configPath, "--format", "json"})
	if code != 1 {
		t.Fatalf("expected custom high-severity finding exit 1, got %d: %s", code, stderr)
	}
	var envelope struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("decoding scan output: %v\n%s", err, stdout)
	}
	for _, finding := range envelope.Findings {
		if finding.RuleID == "CUSTOM_900" {
			return
		}
	}
	t.Fatalf("CUSTOM_900 finding missing from output: %s", stdout)
}

func TestScan_InvalidLocalCustomRuleIsRejected(t *testing.T) {
	root := t.TempDir()
	skill := []byte(`---
name: valid-custom-test
description: A well-documented skill used to verify invalid custom rule diagnostics.
---
This skill contains enough explanatory prose to avoid unrelated quality findings during the validation regression test.
`)
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), skill, 0o600); err != nil {
		t.Fatalf("writing governed file: %v", err)
	}
	configPath := filepath.Join(root, "invalid-custom.yml")
	invalidConfig := []byte(`custom_rules:
  - id: CUSTOM_901
    name: Mistyped primitive
    severity: high
    file_types: [skill_md]
    match:
      type: content_contans
      value: sentinel
    remediation: Fix the primitive name
`)
	if err := os.WriteFile(configPath, invalidConfig, 0o600); err != nil {
		t.Fatalf("writing invalid custom config: %v", err)
	}

	stdout, stderr, code := runBinary(t, []string{"scan", root, "--config", configPath, "--format", "json"})
	if code != 0 {
		t.Fatalf("invalid custom rule should be skipped with a clean local scan, got %d: %s\n%s", code, stderr, stdout)
	}
	if !strings.Contains(stderr, `unknown match type "content_contans"`) {
		t.Errorf("stderr missing invalid custom-rule diagnostic: %s", stderr)
	}
}

func TestScan_MissingLocalCustomMatchIsRejected(t *testing.T) {
	root := t.TempDir()
	skill := []byte(`---
name: missing-custom-match-test
description: A well-documented skill used to verify missing custom match diagnostics.
---
This skill contains enough explanatory prose to avoid unrelated quality findings during the validation regression test.
`)
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), skill, 0o600); err != nil {
		t.Fatalf("writing governed file: %v", err)
	}
	configPath := filepath.Join(root, "missing-custom-match.yml")
	missingMatchConfig := []byte(`custom_rules:
  - id: CUSTOM_902
    name: Missing match due to typo
    severity: high
    file_types: [skill_md]
    macth:
      type: content_contains
      value: sentinel
    remediation: Fix the match key
`)
	if err := os.WriteFile(configPath, missingMatchConfig, 0o600); err != nil {
		t.Fatalf("writing invalid custom config: %v", err)
	}

	stdout, stderr, code := runBinary(t, []string{"scan", root, "--config", configPath, "--format", "json"})
	if code != 0 {
		t.Fatalf("missing custom match should be skipped with a clean local scan, got %d: %s\n%s", code, stderr, stdout)
	}
	if !strings.Contains(stderr, `"match" must not be empty`) {
		t.Errorf("stderr missing empty custom-match diagnostic: %s", stderr)
	}
}

func TestScan_DiscoversConfigFromScanRoot(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temporary scan root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".bouncerfox.yml"), []byte("ignore:\n  - SKILL.md\n"), 0o600); err != nil {
		t.Fatalf("writing project config: %v", err)
	}
	skillPath := filepath.Join(root, "SKILL.md")
	unsafeSkill := []byte(`---
name: unsafe-skill
description: A documented skill containing a value the scanner would normally reject.
---
This skill exists to verify config discovery from the requested scan root.
api_key: 0123456789abcdef0123456789abcdef
`)
	if err := os.WriteFile(skillPath, unsafeSkill, 0o600); err != nil {
		t.Fatalf("writing governed file: %v", err)
	}

	for _, scanPath := range []string{root, skillPath} {
		_, stderr, code := runBinary(t, []string{"scan", scanPath, "--format", "json"})
		if code != 0 {
			t.Errorf("scan %q: expected discovered ignore config to produce exit 0, got %d: %s", scanPath, code, stderr)
		}
	}
}

func TestScan_WarnsOnGenericParseRejections(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temporary scan root: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		content string
		format  string
	}{
		{
			name:    "malformed frontmatter",
			path:    filepath.Join(root, "SKILL.md"),
			content: "---\nname: [unterminated\n---\nBody\n",
			format:  "YAML",
		},
		{
			name:    "malformed JSON",
			path:    filepath.Join(root, ".mcp.json"),
			content: `{"mcpServers":`,
			format:  "JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(tt.path, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("writing malformed input: %v", err)
			}
			_, stderr, _ := runBinary(t, []string{"scan", tt.path})
			want := fmt.Sprintf("warning: could not parse %s as %s at line 1", tt.path, tt.format)
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr should contain %q, got %q", want, stderr)
			}
		})
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

func TestScan_FileLimitProcesses500thFile(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temporary scan root: %v", err)
	}
	cleanSkill := []byte(`---
name: clean-skill
description: A well-documented skill that performs code review and analysis tasks.
---
This skill reviews code for common issues and suggests improvements.
It follows established coding standards and best practices for the project.
`)

	for i := 1; i <= 500; i++ {
		dir := filepath.Join(root, fmt.Sprintf("%04d", i))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("creating skill directory %d: %v", i, err)
		}
		content := cleanSkill
		if i == 500 {
			content = append(append([]byte(nil), cleanSkill...), []byte("api_key: 0123456789abcdef0123456789abcdef\n")...)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), content, 0o600); err != nil {
			t.Fatalf("writing skill %d: %v", i, err)
		}
	}

	type scanOutput struct {
		Findings []struct {
			Evidence struct {
				File string `json:"file"`
			} `json:"evidence"`
		} `json:"findings"`
	}
	containsFindingFor := func(raw, suffix string) bool {
		t.Helper()
		var output scanOutput
		if err := json.Unmarshal([]byte(raw), &output); err != nil {
			t.Fatalf("decoding scan output: %v\n%s", err, raw)
		}
		for _, finding := range output.Findings {
			if strings.HasSuffix(filepath.Clean(finding.Evidence.File), suffix) {
				return true
			}
		}
		return false
	}

	stdout, stderr, code := runBinary(t, []string{"scan", root, "--format", "json"})
	if code != 1 {
		t.Errorf("500-file scan: expected exit 1, got %d", code)
	}
	if !containsFindingFor(stdout, filepath.Join("0500", "SKILL.md")) {
		t.Error("500-file scan should include a finding from the 500th file")
	}
	if strings.Contains(stderr, "file limit") {
		t.Errorf("500 files should not trigger the file-limit warning: %s", stderr)
	}

	lastDir := filepath.Join(root, "0501")
	if err := os.MkdirAll(lastDir, 0o700); err != nil {
		t.Fatalf("creating 501st skill directory: %v", err)
	}
	lastContent := append(append([]byte(nil), cleanSkill...), []byte("api_key: fedcba9876543210fedcba9876543210\n")...)
	if err := os.WriteFile(filepath.Join(lastDir, "SKILL.md"), lastContent, 0o600); err != nil {
		t.Fatalf("writing 501st skill: %v", err)
	}

	stdout, stderr, code = runBinary(t, []string{"scan", root, "--format", "json"})
	if code != 1 {
		t.Errorf("501-file scan: expected exit 1, got %d", code)
	}
	if !containsFindingFor(stdout, filepath.Join("0500", "SKILL.md")) {
		t.Error("501-file scan should still include a finding from the 500th file")
	}
	if containsFindingFor(stdout, filepath.Join("0501", "SKILL.md")) {
		t.Error("501-file scan should not include the capped 501st file")
	}
	if !strings.Contains(stderr, "file limit (500) reached") {
		t.Errorf("501 files should trigger the file-limit warning: %s", stderr)
	}
}

func TestScan_OversizedFileReportsQA009(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "SKILL.md")
	if err := os.WriteFile(path, bytes.Repeat([]byte("A"), 1024*1024+1), 0o600); err != nil {
		t.Fatalf("writing oversized governed file: %v", err)
	}

	stdout, stderr, code := runBinary(t, []string{"scan", root, "--format", "json"})
	if code != 1 {
		t.Fatalf("oversized file should produce a high-severity finding, got %d: %s", code, stderr)
	}
	finding := findingForRule(t, decodeCLIJSONFindings(t, stdout), "QA_009")
	if finding.Evidence.File != "SKILL.md" {
		t.Errorf("evidence file = %q, want SKILL.md", finding.Evidence.File)
	}
	if !strings.Contains(stderr, "too large for content analysis") {
		t.Errorf("stderr missing oversized-file diagnostic: %s", stderr)
	}
}

// --- Connected mode & offline behavior tests ---

func mockPlatform(t *testing.T, verdict string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config/pull":
			w.Header().Set("ETag", `"test"`)
			w.WriteHeader(200)
			w.Write([]byte("profile: recommended\n"))
		case "/api/v1/scans/upload":
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"scan_id":"test-id","verdict":%q,"reasons":[],"dashboard_url":"http://test/scans/test-id"}`, verdict)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestConnected_PassVerdict_Exit0(t *testing.T) {
	srv := mockPlatform(t, "pass")
	defer srv.Close()
	_, _, code := runBinary(t,
		[]string{"scan", "testdata/clean-skill"},
		"BOUNCERFOX_API_KEY=bf_testkey",
		"BOUNCERFOX_PLATFORM_URL="+srv.URL,
	)
	if code != 0 {
		t.Errorf("connected pass verdict: expected exit 0, got %d", code)
	}
}

func TestConnected_FailVerdict_Exit1(t *testing.T) {
	srv := mockPlatform(t, "fail")
	defer srv.Close()
	_, _, code := runBinary(t,
		[]string{"scan", "testdata/clean-skill"},
		"BOUNCERFOX_API_KEY=bf_testkey",
		"BOUNCERFOX_PLATFORM_URL="+srv.URL,
	)
	if code != 1 {
		t.Errorf("connected fail verdict: expected exit 1, got %d", code)
	}
}

func TestConnected_DryRunUpload(t *testing.T) {
	stdout, _, _ := runBinary(t,
		[]string{"scan", "testdata/bad-skill", "--dry-run-upload", "--format", "json"},
		"BOUNCERFOX_API_KEY=bf_testkey",
		"BOUNCERFOX_PLATFORM_URL=http://localhost:1",
	)
	// The output contains two JSON documents: the scan findings (from --format json)
	// followed by the upload payload (from --dry-run-upload). Extract the last
	// top-level JSON object which is the upload payload.
	lastBrace := strings.LastIndex(stdout, "\n{")
	if lastBrace < 0 {
		// Maybe the payload is the only thing or starts at position 0.
		lastBrace = strings.Index(stdout, "{")
		if lastBrace < 0 {
			t.Fatalf("no JSON object found in output:\n%s", stdout)
		}
	} else {
		lastBrace++ // skip the newline
	}
	jsonPart := stdout[lastBrace:]

	var payload map[string]any
	if err := json.Unmarshal([]byte(jsonPart), &payload); err != nil {
		t.Fatalf("dry-run output is not valid JSON: %v\nJSON part: %s", err, jsonPart)
	}
	if _, ok := payload["findings"]; !ok {
		t.Error("dry-run payload missing 'findings' key")
	}
	if _, ok := payload["version"]; !ok {
		t.Error("dry-run payload missing 'version' key")
	}
}

func mockPlatformDown(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte(`{"error":"server_error","message":"down"}`))
	}))
}

func TestOffline_Warn_FallsBackToLocal(t *testing.T) {
	srv := mockPlatformDown(t)
	defer srv.Close()
	_, _, code := runBinary(t,
		[]string{"scan", "testdata/clean-skill", "--offline-behavior", "warn"},
		"BOUNCERFOX_API_KEY=bf_testkey",
		"BOUNCERFOX_PLATFORM_URL="+srv.URL,
	)
	if code != 0 {
		t.Errorf("offline warn with clean skill: expected exit 0, got %d", code)
	}
}

func TestOffline_FailClosed_Exit2(t *testing.T) {
	srv := mockPlatformDown(t)
	defer srv.Close()
	_, _, code := runBinary(t,
		[]string{"scan", "testdata/clean-skill", "--offline-behavior", "fail-closed"},
		"BOUNCERFOX_API_KEY=bf_testkey",
		"BOUNCERFOX_PLATFORM_URL="+srv.URL,
	)
	if code != 2 {
		t.Errorf("offline fail-closed: expected exit 2, got %d", code)
	}
}

func TestScan_MultiTool_DetectsFindings(t *testing.T) {
	stdout, _, code := runBinary(t, []string{"scan", "testdata/multi-tool"})
	if code != 1 {
		t.Errorf("scan multi-tool: expected exit 1, got %d", code)
	}
	if !strings.Contains(stdout, "SEC_001") {
		t.Error("should detect SEC_001 in .cursorrules or AGENTS.md")
	}
	if !strings.Contains(stdout, "SEC_002") {
		t.Error("should detect SEC_002 in .windsurfrules or copilot-instructions.md")
	}
}

func TestScan_ClaudeExtended_DetectsFindings(t *testing.T) {
	stdout, _, code := runBinary(t, []string{"scan", "testdata/claude-extended"})
	if code != 1 {
		t.Errorf("scan claude-extended: expected exit 1, got %d", code)
	}
	if !strings.Contains(stdout, "SEC_001") {
		t.Error("should detect SEC_001 in .claude/rules/security.md")
	}
	if !strings.Contains(stdout, "SEC_009") {
		t.Error("should detect SEC_009 in hooks/hooks.json")
	}
	if !strings.Contains(stdout, "SEC_011") {
		t.Error("should detect SEC_011 in .lsp.json")
	}
}

func TestScan_ImportRef_DetectsFindings(t *testing.T) {
	stdout, _, code := runBinary(t, []string{"scan", "testdata/import-ref"})
	if code != 1 {
		t.Errorf("scan import-ref: expected exit 1, got %d", code)
	}
	if !strings.Contains(stdout, "SEC_021") {
		t.Error("should detect SEC_021 for dangerous imports")
	}
}

// --- Task 2: connected mode GitHub posting / upload enrichment tests ---

// mockPlatformCapture returns a test server that records upload request bodies.
func mockPlatformCapture(t *testing.T, captured *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config/pull":
			w.Header().Set("ETag", `"test"`)
			w.WriteHeader(200)
			w.Write([]byte("profile: recommended\n"))
		case "/api/v1/scans/upload":
			body, _ := io.ReadAll(r.Body)
			if captured != nil {
				*captured = append(*captured, body...)
			}
			w.WriteHeader(201)
			fmt.Fprint(w, `{"scan_id":"test-id","verdict":"pass","reasons":[],"dashboard_url":""}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

// TestConnected_SkipsGitHubComment verifies that --github-comment is a no-op in
// connected mode (the platform handles GitHub feedback via its App).
// We confirm this by running with an invalid GITHUB_TOKEN and a mock platform;
// if the CLI tried to use the token it would fail, but instead it should exit 0.
func TestConnected_SkipsGitHubComment(t *testing.T) {
	srv := mockPlatform(t, "pass")
	defer srv.Close()
	_, stderr, code := runBinary(t,
		[]string{"scan", "testdata/clean-skill", "--github-comment"},
		"BOUNCERFOX_API_KEY=bf_testkey",
		"BOUNCERFOX_PLATFORM_URL="+srv.URL,
		// Provide an obviously invalid token; if the CLI tried to use it, the
		// GitHub API call would fail and a warning would appear in stderr.
		"GITHUB_TOKEN=invalid-token-should-not-be-used",
	)
	if code != 0 {
		t.Errorf("connected mode with --github-comment: expected exit 0, got %d", code)
	}
	// No GitHub API warning should appear in stderr.
	if strings.Contains(stderr, "PR comment failed") || strings.Contains(stderr, "check run failed") {
		t.Error("connected mode should not attempt GitHub API calls: " + stderr)
	}
}

// TestConnected_PRNumberInUpload verifies that when GITHUB_EVENT_PATH is set to
// a PR event payload, the upload request includes pr_number.
func TestConnected_PRNumberInUpload(t *testing.T) {
	// Write a GitHub Actions PR event JSON file.
	eventFile := filepath.Join(t.TempDir(), "event.json")
	eventJSON := `{"pull_request":{"number":42}}`
	if err := os.WriteFile(eventFile, []byte(eventJSON), 0o600); err != nil {
		t.Fatalf("writing event file: %v", err)
	}

	var captured []byte
	srv := mockPlatformCapture(t, &captured)
	defer srv.Close()

	_, _, code := runBinary(t,
		[]string{"scan", "testdata/clean-skill"},
		"BOUNCERFOX_API_KEY=bf_testkey",
		"BOUNCERFOX_PLATFORM_URL="+srv.URL,
		"GITHUB_EVENT_PATH="+eventFile,
	)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if len(captured) == 0 {
		t.Fatal("no upload body captured")
	}
	var payload map[string]any
	if err := json.Unmarshal(captured, &payload); err != nil {
		t.Fatalf("upload body is not valid JSON: %v\nbody: %s", err, string(captured))
	}
	prNum, ok := payload["pr_number"]
	if !ok {
		t.Error("upload payload missing pr_number field")
	} else if int(prNum.(float64)) != 42 {
		t.Errorf("expected pr_number=42, got %v", prNum)
	}
}

// TestConnected_SkillsInUpload verifies that skill metadata from SKILL.md files
// is included in the upload payload.
func TestConnected_SkillsInUpload(t *testing.T) {
	var captured []byte
	srv := mockPlatformCapture(t, &captured)
	defer srv.Close()

	_, _, code := runBinary(t,
		[]string{"scan", "testdata/clean-skill"},
		"BOUNCERFOX_API_KEY=bf_testkey",
		"BOUNCERFOX_PLATFORM_URL="+srv.URL,
	)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if len(captured) == 0 {
		t.Fatal("no upload body captured")
	}
	var payload map[string]any
	if err := json.Unmarshal(captured, &payload); err != nil {
		t.Fatalf("upload body is not valid JSON: %v\nbody: %s", err, string(captured))
	}
	skillsRaw, ok := payload["skills"]
	if !ok {
		t.Error("upload payload missing skills field")
		return
	}
	skills, ok := skillsRaw.([]any)
	if !ok || len(skills) == 0 {
		t.Error("expected at least one skill in upload payload")
		return
	}
	skill := skills[0].(map[string]any)
	if skill["name"] != "clean-skill" {
		t.Errorf("expected skill name 'clean-skill', got %v", skill["name"])
	}
}
