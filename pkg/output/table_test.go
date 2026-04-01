package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/bouncerfox/cli/pkg/document"
)

func TestFormatTable_GroupedByFile(t *testing.T) {
	findings := []document.ScanFinding{
		{RuleID: "SEC_001", Severity: "critical", Message: "Hardcoded secret detected",
			Evidence:    map[string]any{"file": "/root/src/.cursorrules", "line": 5},
			Remediation: "Remove hardcoded secrets."},
		{RuleID: "SEC_002", Severity: "high", Message: "External URL not in allowlist",
			Evidence:    map[string]any{"file": "/root/src/.cursorrules", "line": 8},
			Remediation: "Verify URL."},
		{RuleID: "SEC_002", Severity: "high", Message: "External URL not in allowlist",
			Evidence:    map[string]any{"file": "/root/src/AGENTS.md", "line": 3},
			Remediation: "Verify URL."},
	}
	var buf bytes.Buffer
	opts := FormatOptions{ScanRoot: "/root/src", Stats: ScanStats{FilesScanned: 5, RulesRun: 34, Duration: 20 * time.Millisecond}}
	err := FormatTable(findings, &buf, opts)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "/root/src/") {
		t.Error("should use relative paths, not absolute")
	}
	if !strings.Contains(out, ".cursorrules") {
		t.Error("should contain .cursorrules filename")
	}
	if !strings.Contains(out, "AGENTS.md") {
		t.Error("should contain AGENTS.md filename")
	}
	if !strings.Contains(out, "3 findings") {
		t.Error("should contain finding count in summary")
	}
}

func TestFormatTable_CleanScan(t *testing.T) {
	var buf bytes.Buffer
	opts := FormatOptions{Stats: ScanStats{FilesScanned: 10, RulesRun: 34, Duration: 15 * time.Millisecond}}
	err := FormatTable(nil, &buf, opts)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "PASS") {
		t.Error("clean scan should show PASS")
	}
	if !strings.Contains(out, "No findings") {
		t.Error("clean scan should say No findings")
	}
}

func TestFormatTable_SummaryOmitsZeroCounts(t *testing.T) {
	findings := []document.ScanFinding{
		{RuleID: "SEC_001", Severity: "critical", Message: "test",
			Evidence: map[string]any{"file": "/root/file.md", "line": 1}},
	}
	var buf bytes.Buffer
	opts := FormatOptions{ScanRoot: "/root", Stats: ScanStats{FilesScanned: 1, RulesRun: 34, Duration: time.Millisecond}}
	_ = FormatTable(findings, &buf, opts)
	out := buf.String()
	if strings.Contains(out, "0 warn") || strings.Contains(out, "0 info") {
		t.Error("summary should omit zero counts")
	}
}

func TestFormatTable_SkippedCount(t *testing.T) {
	var buf bytes.Buffer
	opts := FormatOptions{Stats: ScanStats{FilesScanned: 10, RulesRun: 34, Skipped: 3, Duration: time.Millisecond}}
	_ = FormatTable(nil, &buf, opts)
	out := buf.String()
	if !strings.Contains(out, "3 skipped") {
		t.Error("should show skipped count")
	}
}

func TestFormatTable_NoColorWhenFlagged(t *testing.T) {
	findings := []document.ScanFinding{
		{RuleID: "SEC_001", Severity: "critical", Message: "test",
			Evidence: map[string]any{"file": "file.md", "line": 1}},
	}
	var buf bytes.Buffer
	opts := FormatOptions{NoColor: true, Stats: ScanStats{FilesScanned: 1, RulesRun: 1, Duration: time.Millisecond}}
	_ = FormatTable(findings, &buf, opts)
	out := buf.String()
	if strings.Contains(out, "\033[") {
		t.Error("should not contain ANSI escape codes with NoColor")
	}
}

func TestFormatTable_GroupBySeverity(t *testing.T) {
	findings := []document.ScanFinding{
		{RuleID: "QA_003", Severity: "warn", Message: "Missing version",
			Evidence: map[string]any{"file": "/root/b.md", "line": 3}},
		{RuleID: "SEC_001", Severity: "critical", Message: "Hardcoded secret",
			Evidence: map[string]any{"file": "/root/a.md", "line": 5}},
		{RuleID: "SEC_002", Severity: "high", Message: "External URL",
			Evidence: map[string]any{"file": "/root/c.md", "line": 8}},
		{RuleID: "SEC_001", Severity: "critical", Message: "Another secret",
			Evidence: map[string]any{"file": "/root/d.md", "line": 1}},
	}
	var buf bytes.Buffer
	opts := FormatOptions{GroupBy: "severity", ScanRoot: "/root",
		Stats: ScanStats{FilesScanned: 4, RulesRun: 34, Duration: time.Millisecond}}
	err := FormatTable(findings, &buf, opts)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Critical should appear before high, high before warn.
	critIdx := strings.Index(out, "critical")
	highIdx := strings.Index(out, "high")
	warnIdx := strings.Index(out, "warn")
	if critIdx > highIdx || highIdx > warnIdx {
		t.Errorf("severity groups not in order: critical@%d high@%d warn@%d", critIdx, highIdx, warnIdx)
	}

	// Entries should include file path inline.
	if !strings.Contains(out, "a.md:5") {
		t.Error("severity mode should show file:line inline")
	}

	// Finding count in headers.
	if !strings.Contains(out, "(2 findings)") {
		t.Error("critical group should show (2 findings)")
	}
	if !strings.Contains(out, "(1 finding)") {
		t.Error("singular finding count should say '1 finding'")
	}

	// Entries within severity group sorted by file path.
	aIdx := strings.Index(out, "a.md:5")
	dIdx := strings.Index(out, "d.md:1")
	if aIdx > dIdx {
		t.Error("within critical group, a.md should come before d.md")
	}
}

func TestFormatTable_GroupByRule(t *testing.T) {
	findings := []document.ScanFinding{
		{RuleID: "QA_003", Severity: "warn", Message: "Missing version",
			Evidence: map[string]any{"file": "/root/a.md", "line": 3}},
		{RuleID: "SEC_001", Severity: "critical", Message: "Hardcoded secret",
			Evidence: map[string]any{"file": "/root/b.md", "line": 5}},
		{RuleID: "QA_003", Severity: "warn", Message: "Missing version again",
			Evidence: map[string]any{"file": "/root/c.md", "line": 8}},
	}
	ruleNames := map[string]string{
		"SEC_001": "Hardcoded Secret",
		"QA_003":  "Missing Version",
	}
	var buf bytes.Buffer
	opts := FormatOptions{GroupBy: "rule", RuleNames: ruleNames, ScanRoot: "/root",
		Stats: ScanStats{FilesScanned: 3, RulesRun: 34, Duration: time.Millisecond}}
	err := FormatTable(findings, &buf, opts)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// SEC_001 (critical) should appear before QA_003 (warn).
	secIdx := strings.Index(out, "SEC_001 Hardcoded Secret")
	qaIdx := strings.Index(out, "QA_003 Missing Version")
	if secIdx < 0 {
		t.Fatal("expected SEC_001 with rule name in header")
	}
	if qaIdx < 0 {
		t.Fatal("expected QA_003 with rule name in header")
	}
	if secIdx > qaIdx {
		t.Error("SEC_001 (critical) should appear before QA_003 (warn)")
	}

	// File:line should appear inline.
	if !strings.Contains(out, "b.md:5") {
		t.Error("rule mode should show file:line inline")
	}

	// Finding counts.
	if !strings.Contains(out, "(2 findings)") {
		t.Error("QA_003 group should show (2 findings)")
	}
}

func TestFormatTable_GroupByRuleFallbackNoName(t *testing.T) {
	findings := []document.ScanFinding{
		{RuleID: "CUSTOM_001", Severity: "high", Message: "Custom issue",
			Evidence: map[string]any{"file": "test.md", "line": 1}},
	}
	var buf bytes.Buffer
	opts := FormatOptions{GroupBy: "rule",
		Stats: ScanStats{FilesScanned: 1, RulesRun: 1, Duration: time.Millisecond}}
	_ = FormatTable(findings, &buf, opts)
	out := buf.String()
	// Should use just rule ID when RuleNames is nil.
	if !strings.Contains(out, "CUSTOM_001") {
		t.Error("should show rule ID even without rule names")
	}
}

func TestFormatTable_GroupByRuleSortSameSeverity(t *testing.T) {
	findings := []document.ScanFinding{
		{RuleID: "SEC_002", Severity: "high", Message: "URL issue",
			Evidence: map[string]any{"file": "a.md", "line": 1}},
		{RuleID: "CFG_001", Severity: "high", Message: "Config issue",
			Evidence: map[string]any{"file": "b.md", "line": 2}},
	}
	var buf bytes.Buffer
	opts := FormatOptions{GroupBy: "rule",
		Stats: ScanStats{FilesScanned: 2, RulesRun: 2, Duration: time.Millisecond}}
	_ = FormatTable(findings, &buf, opts)
	out := buf.String()
	// CFG_001 should come before SEC_002 alphabetically.
	cfgIdx := strings.Index(out, "CFG_001")
	secIdx := strings.Index(out, "SEC_002")
	if cfgIdx > secIdx {
		t.Error("same-severity rules should be sorted alphabetically: CFG_001 before SEC_002")
	}
}

func TestFormatTable_GroupByRuleMixedSeverity(t *testing.T) {
	// A rule with findings at different severity levels should sort by highest.
	findings := []document.ScanFinding{
		{RuleID: "QA_007", Severity: "warn", Message: "Warn finding",
			Evidence: map[string]any{"file": "a.md", "line": 1}},
		{RuleID: "SEC_001", Severity: "high", Message: "High finding",
			Evidence: map[string]any{"file": "b.md", "line": 2}},
		{RuleID: "SEC_001", Severity: "critical", Message: "Critical finding",
			Evidence: map[string]any{"file": "c.md", "line": 3}},
	}
	var buf bytes.Buffer
	opts := FormatOptions{GroupBy: "rule",
		Stats: ScanStats{FilesScanned: 3, RulesRun: 2, Duration: time.Millisecond}}
	_ = FormatTable(findings, &buf, opts)
	out := buf.String()
	// SEC_001 has a critical finding, so it should appear before QA_007 (warn).
	secIdx := strings.Index(out, "SEC_001")
	qaIdx := strings.Index(out, "QA_007")
	if secIdx > qaIdx {
		t.Error("SEC_001 (has critical) should sort before QA_007 (warn)")
	}
}

func TestFormatTable_GroupByEmptyDefaultsToFile(t *testing.T) {
	findings := []document.ScanFinding{
		{RuleID: "SEC_001", Severity: "critical", Message: "test",
			Evidence: map[string]any{"file": "/root/test.md", "line": 1}},
	}
	var buf1, buf2 bytes.Buffer
	opts := FormatOptions{ScanRoot: "/root",
		Stats: ScanStats{FilesScanned: 1, RulesRun: 1, Duration: time.Millisecond}}
	_ = FormatTable(findings, &buf1, opts)

	opts.GroupBy = "file"
	_ = FormatTable(findings, &buf2, opts)

	if buf1.String() != buf2.String() {
		t.Error("empty GroupBy should produce same output as GroupBy='file'")
	}
}

func TestFormatTable_UnknownFileInSeverityMode(t *testing.T) {
	findings := []document.ScanFinding{
		{RuleID: "SEC_001", Severity: "critical", Message: "test",
			Evidence: map[string]any{"line": 5}},
	}
	var buf bytes.Buffer
	opts := FormatOptions{GroupBy: "severity",
		Stats: ScanStats{FilesScanned: 1, RulesRun: 1, Duration: time.Millisecond}}
	_ = FormatTable(findings, &buf, opts)
	out := buf.String()
	if !strings.Contains(out, "(unknown):5") {
		t.Errorf("should show (unknown):5 for finding with no file, got:\n%s", out)
	}
}

func TestFormatTable_SeverityColoredSummary(t *testing.T) {
	findings := []document.ScanFinding{
		{RuleID: "SEC_001", Severity: "critical", Message: "test",
			Evidence: map[string]any{"file": "f.md", "line": 1}},
		{RuleID: "QA_003", Severity: "warn", Message: "test",
			Evidence: map[string]any{"file": "f.md", "line": 2}},
	}
	var buf bytes.Buffer
	// IsTTY=true enables colors.
	opts := FormatOptions{IsTTY: true, Stats: ScanStats{FilesScanned: 1, RulesRun: 2, Duration: time.Millisecond}}
	_ = FormatTable(findings, &buf, opts)
	out := buf.String()
	// Should contain ANSI codes in the summary line for severity counts.
	if !strings.Contains(out, "\033[1;31m1 critical\033[0m") {
		t.Errorf("expected red bold for critical count, got:\n%s", out)
	}
	if !strings.Contains(out, "\033[33m1 warn\033[0m") {
		t.Errorf("expected yellow for warn count, got:\n%s", out)
	}
}

func TestFormatTable_SeverityColoredSummary_NoColor(t *testing.T) {
	findings := []document.ScanFinding{
		{RuleID: "SEC_001", Severity: "critical", Message: "test",
			Evidence: map[string]any{"file": "f.md", "line": 1}},
	}
	var buf bytes.Buffer
	opts := FormatOptions{NoColor: true, Stats: ScanStats{FilesScanned: 1, RulesRun: 1, Duration: time.Millisecond}}
	_ = FormatTable(findings, &buf, opts)
	out := buf.String()
	if strings.Contains(out, "\033[") {
		t.Error("should not contain ANSI codes with NoColor")
	}
	if !strings.Contains(out, "1 critical") {
		t.Error("summary should still show severity count without color")
	}
}

func TestFormatTable_FileGroupHeaderHasCount(t *testing.T) {
	findings := []document.ScanFinding{
		{RuleID: "SEC_001", Severity: "critical", Message: "test1",
			Evidence: map[string]any{"file": "/root/f.md", "line": 1}},
		{RuleID: "SEC_002", Severity: "high", Message: "test2",
			Evidence: map[string]any{"file": "/root/f.md", "line": 2}},
	}
	var buf bytes.Buffer
	opts := FormatOptions{ScanRoot: "/root",
		Stats: ScanStats{FilesScanned: 1, RulesRun: 2, Duration: time.Millisecond}}
	_ = FormatTable(findings, &buf, opts)
	out := buf.String()
	if !strings.Contains(out, "f.md (2 findings)") {
		t.Errorf("file header should include finding count, got:\n%s", out)
	}
}
