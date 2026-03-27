package upload

import (
	"strings"
	"testing"

	"github.com/bouncerfox/cli/pkg/document"
)

// sampleFindings provides a small set of findings used across tests.
var sampleFindings = []document.ScanFinding{
	{
		RuleID:      "SEC_001",
		Severity:    document.SeverityCritical,
		Message:     "hardcoded secret",
		Evidence:    map[string]any{"file": "path/to/CLAUDE.md", "line": 5},
		Remediation: "rotate credentials",
	},
	{
		RuleID:   "QA_001",
		Severity: document.SeverityWarn,
		Message:  "missing description",
		Evidence: map[string]any{"file": "SKILL.md", "line": 1},
	},
}

// ---- BuildWireFindings: finding shape --------------------------------------

func TestPayload_FindingShape(t *testing.T) {
	wire := BuildWireFindings(sampleFindings, false, false)
	if len(wire) != 2 {
		t.Fatalf("expected 2 wire findings, got %d", len(wire))
	}
	first := wire[0]
	if first.RuleID != "SEC_001" {
		t.Errorf("expected rule_id SEC_001, got %q", first.RuleID)
	}
	if first.Severity != "critical" {
		t.Errorf("expected severity critical, got %q", first.Severity)
	}
	if first.File != "path/to/CLAUDE.md" {
		t.Errorf("expected file path/to/CLAUDE.md, got %q", first.File)
	}
	if first.Line != 5 {
		t.Errorf("expected line 5, got %d", first.Line)
	}
}

func TestPayload_StripPaths_UsesBasename(t *testing.T) {
	wire := BuildWireFindings(sampleFindings, true, false)
	if wire[0].File != "CLAUDE.md" {
		t.Errorf("StripPaths: expected file=CLAUDE.md, got %q", wire[0].File)
	}
}

func TestPayload_Anonymous_StripsFilePaths(t *testing.T) {
	wire := BuildWireFindings(sampleFindings, false, true)
	for _, wf := range wire {
		if wf.File != "" {
			t.Errorf("anonymous mode should strip file field, got %q", wf.File)
		}
		if wf.Line != 0 {
			t.Errorf("anonymous mode should strip line field, got %d", wf.Line)
		}
	}
}

// ---- safety assertions -----------------------------------------------------

func TestPayload_NeverContainsSnippetOrEvidence(t *testing.T) {
	findings := []document.ScanFinding{{
		RuleID:   "SEC_001",
		Severity: document.SeverityCritical,
		Message:  "secret found",
		Evidence: map[string]any{
			"file": "test.md", "line": 5,
			"snippet": "sk-SECRETVALUE", "matched": "sk-SECRETVALUE",
		},
		Remediation: "remove it",
	}}
	wire := BuildWireFindings(findings, false, false)
	if len(wire) != 1 {
		t.Fatalf("expected 1 wire finding, got %d", len(wire))
	}
	wf := wire[0]
	if strings.Contains(wf.Message, "SECRETVALUE") {
		t.Error("wire finding message must not contain matched secret values")
	}
	if strings.Contains(wf.Fingerprint, "SECRETVALUE") {
		t.Error("wire finding fingerprint must not contain matched secret values")
	}
	if wf.File == "sk-SECRETVALUE" || wf.Remediation == "sk-SECRETVALUE" {
		t.Error("wire finding must never expose raw evidence values")
	}
}

func TestPayload_FlatFindingFields(t *testing.T) {
	findings := []document.ScanFinding{{
		RuleID:   "SEC_002",
		Severity: document.SeverityHigh,
		Message:  "external URL",
		Evidence: map[string]any{"file": "SKILL.md", "line": 10},
	}}
	wire := BuildWireFindings(findings, false, false)
	if len(wire) != 1 {
		t.Fatalf("expected 1 wire finding, got %d", len(wire))
	}
	wf := wire[0]
	if wf.File != "SKILL.md" {
		t.Errorf("expected top-level file field SKILL.md, got %q", wf.File)
	}
	if wf.Line != 10 {
		t.Errorf("expected top-level line field 10, got %d", wf.Line)
	}
}

func TestPayload_MessageCappedAt500(t *testing.T) {
	long := strings.Repeat("x", 600)
	findings := []document.ScanFinding{{
		RuleID:   "QA_001",
		Severity: document.SeverityWarn,
		Message:  long,
	}}
	wire := BuildWireFindings(findings, false, false)
	if len(wire[0].Message) > 500 {
		t.Errorf("message should be capped at 500 chars, got %d", len(wire[0].Message))
	}
}

// ---- IdempotencyKey --------------------------------------------------------

func TestIdempotencyKey_Deterministic(t *testing.T) {
	k1 := IdempotencyKey("github:a/b", "sha1", "cfghash", []string{"fp1", "fp2"})
	k2 := IdempotencyKey("github:a/b", "sha1", "cfghash", []string{"fp1", "fp2"})
	if k1 != k2 {
		t.Error("same inputs should produce same key")
	}
}

func TestIdempotencyKey_OrderIndependent(t *testing.T) {
	k1 := IdempotencyKey("t", "c", "h", []string{"b", "a"})
	k2 := IdempotencyKey("t", "c", "h", []string{"a", "b"})
	if k1 != k2 {
		t.Error("fingerprint order should not matter")
	}
}

func TestIdempotencyKey_DifferentInputsDiffer(t *testing.T) {
	k1 := IdempotencyKey("t1", "c", "h", nil)
	k2 := IdempotencyKey("t2", "c", "h", nil)
	if k1 == k2 {
		t.Error("different targets should produce different keys")
	}
}
