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
