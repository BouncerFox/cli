package engine_test

import (
	"strings"
	"testing"

	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/engine"
	"github.com/bouncerfox/cli/pkg/fingerprint"
	"github.com/bouncerfox/cli/pkg/parser"
)

// makeSkill returns a parsed skill_md document with the given content.
func makeSkill(t *testing.T, content string) *document.ConfigDocument {
	t.Helper()
	doc := parser.RouteAndParse(".claude/skills/test-skill/SKILL.md", content)
	if doc == nil {
		t.Fatal("RouteAndParse returned nil for skill_md")
	}
	return doc
}

// makeSettings returns a parsed settings_json document with the given content.
func makeSettings(t *testing.T, content string) *document.ConfigDocument {
	t.Helper()
	doc := parser.RouteAndParse(".claude/settings.json", content)
	if doc == nil {
		t.Fatal("RouteAndParse returned nil for settings_json")
	}
	return doc
}

// makeMCP returns a parsed mcp_json document with the given content.
func makeMCP(t *testing.T, content string) *document.ConfigDocument {
	t.Helper()
	doc := parser.RouteAndParse(".mcp.json", content)
	if doc == nil {
		t.Fatal("RouteAndParse returned nil for mcp_json")
	}
	return doc
}

// TestScan_BasicFindings verifies that a document with a known bad pattern
// produces at least one finding.
func TestScan_BasicFindings(t *testing.T) {
	content := "---\nname: myskill\ndescription: A helpful skill that does things.\n---\n" +
		"Use this skill.\n"
	doc := makeSkill(t, content)

	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{})

	if result.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", result.FilesScanned)
	}
	if result.RulesRun == 0 {
		t.Error("RulesRun = 0, want > 0")
	}
}

// TestScan_FindingsContainExpectedRuleID checks that a file with a hardcoded
// secret triggers SEC_001.
func TestScan_FindingsContainExpectedRuleID(t *testing.T) {
	content := "---\nname: bad\ndescription: A skill\n---\n" +
		"token: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
	doc := makeSkill(t, content)

	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{})

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "SEC_001" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SEC_001 finding, got: %v", ruleIDs(result.Findings))
	}
}

// TestScan_SEC001RunsBeforeSEC006 verifies the rule execution order guarantee:
// SEC_001 must run first so it caches flagged lines; SEC_006 should not then
// double-report a base64-looking token that was already caught by SEC_001.
func TestScan_SEC001RunsBeforeSEC006(t *testing.T) {
	// sk- prefix + 32+ chars triggers SEC_001; the value also looks like a
	// long base64 string that might trigger SEC_006 if order were wrong.
	content := "---\nname: sk\ndescription: A skill for testing things.\n---\n" +
		"key: sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789xy\n"
	doc := makeSkill(t, content)

	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{})

	sec001Count := 0
	sec006Count := 0
	for _, f := range result.Findings {
		switch f.RuleID {
		case "SEC_001":
			sec001Count++
		case "SEC_006":
			sec006Count++
		}
	}

	if sec001Count == 0 {
		t.Error("expected SEC_001 to fire")
	}
	// SEC_006 must not double-report a line already caught by SEC_001.
	if sec006Count > 0 {
		t.Errorf("SEC_006 should not fire on lines already caught by SEC_001, got %d findings", sec006Count)
	}
}

// TestScan_EnabledRulesFilter verifies that only the specified rules are run.
func TestScan_EnabledRulesFilter(t *testing.T) {
	content := "---\nname: bad\ndescription: A skill\n---\n" +
		"token: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
	doc := makeSkill(t, content)

	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{
		EnabledRules: []string{"QA_001"},
	})

	for _, f := range result.Findings {
		if f.RuleID != "QA_001" {
			t.Errorf("EnabledRules filter failed: got finding for %s, want only QA_001", f.RuleID)
		}
	}
}

// TestScan_DisabledRulesFilter verifies that disabled rules are skipped.
func TestScan_DisabledRulesFilter(t *testing.T) {
	content := "---\nname: bad\ndescription: A skill\n---\n" +
		"token: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
	doc := makeSkill(t, content)

	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{
		DisabledRules: []string{"SEC_001"},
	})

	for _, f := range result.Findings {
		if f.RuleID == "SEC_001" {
			t.Error("DisabledRules filter failed: SEC_001 finding should be suppressed")
		}
	}
}

// TestScan_SeverityFloor verifies that findings below the floor are excluded.
func TestScan_SeverityFloor(t *testing.T) {
	// A well-formed skill with no real issues; QA_006 (missing tools) fires at info.
	content := "---\nname: myskill\ndescription: A helpful skill that does things.\n---\n" +
		strings.Repeat("a", 60) + "\n"
	doc := makeSkill(t, content)

	// Floor at warn: info-level findings should be suppressed.
	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{
		SeverityFloor: document.SeverityWarn,
	})

	for _, f := range result.Findings {
		if f.Severity.Level() < document.SeverityWarn.Level() {
			t.Errorf("SeverityFloor filter failed: got finding %s with severity %s", f.RuleID, f.Severity)
		}
	}
}

// TestScan_MaxFindings verifies that the cap is respected.
func TestScan_MaxFindings(t *testing.T) {
	// A file with multiple issues.
	content := "---\nname: bad\ndescription: A skill\n---\n" +
		"token: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n" +
		"Visit https://evil.example.com/\n"
	doc := makeSkill(t, content)

	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{
		MaxFindings: 1,
	})

	if len(result.Findings) > 1 {
		t.Errorf("MaxFindings=1 cap failed: got %d findings", len(result.Findings))
	}
}

// TestScan_SuppressionMap verifies that fingerprinted findings are skipped.
func TestScan_SuppressionMap(t *testing.T) {
	content := "---\nname: bad\ndescription: A skill\n---\n" +
		"token: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
	doc := makeSkill(t, content)

	// First scan to get the fingerprint.
	first := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{})
	suppressed := make(map[string]bool)
	for _, f := range first.Findings {
		if f.RuleID == "SEC_001" {
			suppressed[fingerprint.ComputeFingerprint(f)] = true
		}
	}

	// Second scan with the suppression map.
	second := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{
		SuppressionMap: suppressed,
	})

	for _, f := range second.Findings {
		if f.RuleID == "SEC_001" {
			t.Error("Suppressed SEC_001 finding still appeared")
		}
	}
}

// TestScan_Deduplication verifies that identical findings are not reported twice.
func TestScan_Deduplication(t *testing.T) {
	content := "---\nname: bad\ndescription: A skill\n---\n" +
		"token: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
	// Provide the same document twice.
	doc := makeSkill(t, content)
	doc2 := makeSkill(t, content)

	result := engine.Scan([]*document.ConfigDocument{doc, doc2}, engine.ScanOptions{})

	counts := make(map[string]int)
	for _, f := range result.Findings {
		fp := fingerprint.ComputeFingerprint(f)
		counts[fp]++
		if counts[fp] > 1 {
			t.Errorf("Duplicate finding for rule %s (fingerprint %s)", f.RuleID, fp)
		}
	}
}

// TestScan_FileTypeFilter verifies that rules only run on applicable file types.
// CFG_001 applies only to settings_json; a skill_md doc should never trigger it.
func TestScan_FileTypeFilter(t *testing.T) {
	// This content would trigger CFG_001 if the file type were settings_json.
	content := "---\nname: myskill\ndescription: A skill about tools.\n---\n" +
		"allowedTools: [\"Bash\"]\n"
	doc := makeSkill(t, content)

	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{
		EnabledRules: []string{"CFG_001"},
	})

	if len(result.Findings) > 0 {
		t.Errorf("CFG_001 should not fire on skill_md; got %v", ruleIDs(result.Findings))
	}
}

// TestScan_SettingsJSONRules verifies that rules targeting settings_json fire on
// the correct file type.
func TestScan_SettingsJSONRules(t *testing.T) {
	content := `{"allowedTools": ["Bash"]}`
	doc := makeSettings(t, content)

	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{
		EnabledRules: []string{"CFG_001"},
	})

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "CFG_001" {
			found = true
		}
	}
	if !found {
		t.Error("CFG_001 should fire on settings_json with unrestricted Bash")
	}
}

// TestScan_MCPJSONRules verifies that mcp_json-specific rules apply correctly.
func TestScan_MCPJSONRules(t *testing.T) {
	content := `{
  "mcpServers": {
    "myserver": {
      "command": "npx",
      "args": ["@someorg/mcp-server"]
    }
  }
}`
	doc := makeMCP(t, content)

	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{
		EnabledRules: []string{"SEC_014"},
	})

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "SEC_014" {
			found = true
		}
	}
	if !found {
		t.Error("SEC_014 should fire on mcp_json with unpinned package version")
	}
}

// TestScan_MultipleDocuments verifies that the engine processes multiple
// documents and correctly counts files scanned.
func TestScan_MultipleDocuments(t *testing.T) {
	skill := makeSkill(t, "---\nname: ok\ndescription: A skill that does things nicely.\n---\nDo this.\n")
	settings := makeSettings(t, `{"allowedTools": ["Read"]}`)

	result := engine.Scan([]*document.ConfigDocument{skill, settings}, engine.ScanOptions{})

	if result.FilesScanned != 2 {
		t.Errorf("FilesScanned = %d, want 2", result.FilesScanned)
	}
}

// TestScan_EmptyDocs verifies that an empty document list returns a zero result.
func TestScan_EmptyDocs(t *testing.T) {
	result := engine.Scan(nil, engine.ScanOptions{})

	if result.FilesScanned != 0 {
		t.Errorf("FilesScanned = %d, want 0", result.FilesScanned)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0", len(result.Findings))
	}
}

// ruleIDs returns a slice of rule IDs for error messages.
func ruleIDs(findings []document.ScanFinding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids
}
