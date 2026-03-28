package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/fingerprint"
	"github.com/bouncerfox/cli/pkg/output"
)

var testFindings = []document.ScanFinding{
	{
		RuleID:   "SEC_001",
		Severity: document.SeverityCritical,
		Message:  "hardcoded secret detected",
		Evidence: map[string]any{
			"file":    "CLAUDE.md",
			"line":    5,
			"snippet": "api_key=abc123",
		},
		Remediation: "remove secret and rotate credentials",
	},
	{
		RuleID:   "QA_001",
		Severity: document.SeverityHigh,
		Message:  "missing description field",
		Evidence: map[string]any{
			"file": "SKILL.md",
			"line": 1,
		},
		Remediation: "add a description field to frontmatter",
	},
	{
		RuleID:   "CFG_001",
		Severity: document.SeverityWarn,
		Message:  "deprecated config key",
		Evidence: map[string]any{
			"file": ".claude/settings.json",
			"line": 3,
		},
		Remediation: "migrate to new config format",
	},
	{
		RuleID:   "QA_002",
		Severity: document.SeverityInfo,
		Message:  "long description",
		Evidence: map[string]any{
			"file": "SKILL.md",
			"line": 10,
		},
		Remediation: "shorten description",
	},
}

// ---------------------------------------------------------------------------
// Table formatter
// ---------------------------------------------------------------------------

func TestFormatTable_ContainsRuleIDs(t *testing.T) {
	var buf bytes.Buffer
	if err := output.FormatTable(testFindings, &buf, output.FormatOptions{}); err != nil {
		t.Fatalf("FormatTable returned error: %v", err)
	}
	out := buf.String()
	for _, f := range testFindings {
		if !strings.Contains(out, f.RuleID) {
			t.Errorf("output missing rule_id %q", f.RuleID)
		}
	}
}

func TestFormatTable_ContainsMessages(t *testing.T) {
	var buf bytes.Buffer
	if err := output.FormatTable(testFindings, &buf, output.FormatOptions{}); err != nil {
		t.Fatalf("FormatTable returned error: %v", err)
	}
	out := buf.String()
	for _, f := range testFindings {
		if !strings.Contains(out, f.Message) {
			t.Errorf("output missing message %q", f.Message)
		}
	}
}

func TestFormatTable_ContainsSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := output.FormatTable(testFindings, &buf, output.FormatOptions{}); err != nil {
		t.Fatalf("FormatTable returned error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "4 findings") {
		t.Errorf("expected summary with '4 findings', got:\n%s", out)
	}
	// counts per severity
	if !strings.Contains(out, "1 critical") {
		t.Errorf("expected '1 critical' in summary")
	}
	if !strings.Contains(out, "1 high") {
		t.Errorf("expected '1 high' in summary")
	}
	if !strings.Contains(out, "1 warn") {
		t.Errorf("expected '1 warn' in summary")
	}
	if !strings.Contains(out, "1 info") {
		t.Errorf("expected '1 info' in summary")
	}
}

func TestFormatTable_ContainsFileLine(t *testing.T) {
	var buf bytes.Buffer
	if err := output.FormatTable(testFindings, &buf, output.FormatOptions{}); err != nil {
		t.Fatalf("FormatTable returned error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "CLAUDE.md") {
		t.Errorf("expected file name in output")
	}
}

func TestFormatTable_ContainsRemediation(t *testing.T) {
	var buf bytes.Buffer
	if err := output.FormatTable(testFindings, &buf, output.FormatOptions{}); err != nil {
		t.Fatalf("FormatTable returned error: %v", err)
	}
	out := buf.String()
	for _, f := range testFindings {
		if !strings.Contains(out, f.Remediation) {
			t.Errorf("output missing remediation %q", f.Remediation)
		}
	}
}

func TestFormatTable_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := output.FormatTable(nil, &buf, output.FormatOptions{}); err != nil {
		t.Fatalf("FormatTable with nil returned error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No findings") {
		t.Errorf("expected 'No findings' in empty summary, got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// JSON formatter
// ---------------------------------------------------------------------------

func TestFormatJSON_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := output.FormatJSON(testFindings, &buf); err != nil {
		t.Fatalf("FormatJSON returned error: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
}

func TestFormatJSON_Version(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatJSON(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)
	if result["version"] != "1.0" {
		t.Errorf("expected version 1.0, got %v", result["version"])
	}
}

func TestFormatJSON_FindingsArray(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatJSON(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)

	findings, ok := result["findings"].([]any)
	if !ok {
		t.Fatalf("findings is not an array")
	}
	if len(findings) != len(testFindings) {
		t.Errorf("expected %d findings, got %d", len(testFindings), len(findings))
	}
}

func TestFormatJSON_FindingShape(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatJSON(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)

	findings := result["findings"].([]any)
	first := findings[0].(map[string]any)

	requiredKeys := []string{"rule_id", "severity", "message", "evidence", "remediation", "fingerprint"}
	for _, k := range requiredKeys {
		if _, ok := first[k]; !ok {
			t.Errorf("finding missing key %q", k)
		}
	}
}

func TestFormatJSON_Fingerprint(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatJSON(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)

	findings := result["findings"].([]any)
	first := findings[0].(map[string]any)

	expected := fingerprint.ComputeFingerprint(testFindings[0])
	if first["fingerprint"] != expected {
		t.Errorf("fingerprint mismatch: expected %s, got %v", expected, first["fingerprint"])
	}
}

func TestFormatJSON_Summary(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatJSON(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)

	summary, ok := result["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary is missing or not an object")
	}
	if int(summary["total"].(float64)) != 4 {
		t.Errorf("expected total 4, got %v", summary["total"])
	}
	bySev := summary["by_severity"].(map[string]any)
	if int(bySev["critical"].(float64)) != 1 {
		t.Errorf("expected 1 critical, got %v", bySev["critical"])
	}
}

func TestFormatJSON_EvidenceShape(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatJSON(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)

	findings := result["findings"].([]any)
	first := findings[0].(map[string]any)
	ev := first["evidence"].(map[string]any)

	if ev["file"] != "CLAUDE.md" {
		t.Errorf("expected evidence.file CLAUDE.md, got %v", ev["file"])
	}
	if int(ev["line"].(float64)) != 5 {
		t.Errorf("expected evidence.line 5, got %v", ev["line"])
	}
	if ev["snippet"] != "api_key=abc123" {
		t.Errorf("expected snippet, got %v", ev["snippet"])
	}
}

func TestFormatJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := output.FormatJSON(nil, &buf); err != nil {
		t.Fatalf("FormatJSON with nil returned error: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("empty output is not valid JSON: %v", err)
	}
	findings := result["findings"].([]any)
	if len(findings) != 0 {
		t.Errorf("expected empty findings array")
	}
}

// ---------------------------------------------------------------------------
// SARIF formatter
// ---------------------------------------------------------------------------

func TestFormatSARIF_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := output.FormatSARIF(testFindings, &buf); err != nil {
		t.Fatalf("FormatSARIF returned error: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, buf.String())
	}
}

func TestFormatSARIF_Schema(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatSARIF(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)

	if result["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", result["version"])
	}
	if result["$schema"] == nil {
		t.Error("missing $schema")
	}
}

func TestFormatSARIF_ToolDriver(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatSARIF(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)

	runs := result["runs"].([]any)
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)

	if driver["name"] != "BouncerFox" {
		t.Errorf("expected driver name BouncerFox, got %v", driver["name"])
	}
	if driver["version"] == nil {
		t.Error("driver missing version")
	}
	if driver["informationUri"] == nil {
		t.Error("driver missing informationUri")
	}
}

func TestFormatSARIF_Results(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatSARIF(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)

	runs := result["runs"].([]any)
	run := runs[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok {
		t.Fatal("results is not an array")
	}
	if len(results) != len(testFindings) {
		t.Errorf("expected %d results, got %d", len(testFindings), len(results))
	}
}

func TestFormatSARIF_LevelMapping(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatSARIF(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)

	runs := result["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)

	// testFindings: critical, high, warn, info
	expected := []string{"error", "error", "warning", "note"}
	for i, r := range results {
		res := r.(map[string]any)
		if res["level"] != expected[i] {
			t.Errorf("result[%d]: expected level %q, got %v", i, expected[i], res["level"])
		}
	}
}

func TestFormatSARIF_RuleIDAndMessage(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatSARIF(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)

	runs := result["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	first := results[0].(map[string]any)

	if first["ruleId"] != "SEC_001" {
		t.Errorf("expected ruleId SEC_001, got %v", first["ruleId"])
	}
	msg := first["message"].(map[string]any)
	if !strings.Contains(msg["text"].(string), "hardcoded secret") {
		t.Errorf("expected message text to contain 'hardcoded secret', got %v", msg["text"])
	}
}

func TestFormatSARIF_LocationURI(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatSARIF(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)

	runs := result["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	first := results[0].(map[string]any)

	locs := first["locations"].([]any)
	loc := locs[0].(map[string]any)
	pl := loc["physicalLocation"].(map[string]any)
	af := pl["artifactLocation"].(map[string]any)
	if af["uri"] != "CLAUDE.md" {
		t.Errorf("expected uri CLAUDE.md, got %v", af["uri"])
	}
	region := pl["region"].(map[string]any)
	if int(region["startLine"].(float64)) != 5 {
		t.Errorf("expected startLine 5, got %v", region["startLine"])
	}
}

func TestFormatSARIF_Rules(t *testing.T) {
	var buf bytes.Buffer
	_ = output.FormatSARIF(testFindings, &buf)
	var result map[string]any
	_ = json.Unmarshal(buf.Bytes(), &result)

	runs := result["runs"].([]any)
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rules, ok := driver["rules"].([]any)
	if !ok {
		t.Fatal("driver.rules is not an array")
	}
	// Should have one entry per unique rule_id (4 distinct rules here)
	if len(rules) != 4 {
		t.Errorf("expected 4 rules in driver, got %d", len(rules))
	}
}

func TestFormatSARIF_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := output.FormatSARIF(nil, &buf); err != nil {
		t.Fatalf("FormatSARIF with nil returned error: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("empty SARIF is not valid JSON: %v", err)
	}
}
