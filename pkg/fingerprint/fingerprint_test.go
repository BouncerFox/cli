package fingerprint_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/fingerprint"
)

// helper computes expected SHA-256 of a pipe-joined component string.
func sha256hex(parts ...string) string {
	raw := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

func TestComputeFingerprint_SnippetTakesPriority(t *testing.T) {
	finding := document.ScanFinding{
		RuleID:   "SEC_001",
		Severity: document.SeverityHigh,
		Evidence: map[string]any{
			"snippet":     "AKIAIOSFODNN7EXAMPLE",
			"key":         "api_key",
			"line_number": 42,
			"file":        "CLAUDE.md",
		},
	}
	got := fingerprint.ComputeFingerprint(finding)
	want := sha256hex("SEC_001", "CLAUDE.md", "AKIAIOSFODNN7EXAMPLE")
	if got != want {
		t.Errorf("snippet priority: got %s, want %s", got, want)
	}
}

func TestComputeFingerprint_KeyFallback(t *testing.T) {
	finding := document.ScanFinding{
		RuleID:   "CFG_001",
		Severity: document.SeverityWarn,
		Evidence: map[string]any{
			"key":         "allowed_tools",
			"line_number": 10,
			"file":        "settings.json",
		},
	}
	got := fingerprint.ComputeFingerprint(finding)
	want := sha256hex("CFG_001", "settings.json", "allowed_tools")
	if got != want {
		t.Errorf("key fallback: got %s, want %s", got, want)
	}
}

func TestComputeFingerprint_FieldFallback(t *testing.T) {
	finding := document.ScanFinding{
		RuleID:   "QA_002",
		Severity: document.SeverityInfo,
		Evidence: map[string]any{
			"field":       "description",
			"line_number": 5,
		},
	}
	got := fingerprint.ComputeFingerprint(finding)
	want := sha256hex("QA_002", "", "description")
	if got != want {
		t.Errorf("field fallback: got %s, want %s", got, want)
	}
}

func TestComputeFingerprint_SortedFallback(t *testing.T) {
	finding := document.ScanFinding{
		RuleID:   "PS_001",
		Severity: document.SeverityHigh,
		Evidence: map[string]any{
			"match":       "ignore previous instructions",
			"category":    "prompt_injection",
			"line":        7,
			"line_number": 7,
			"file":        "SKILL.md",
		},
	}
	got := fingerprint.ComputeFingerprint(finding)
	// Positional fields "line", "line_number", "file" excluded from stableEvidence.
	// file path "SKILL.md" is included as the second component.
	// Remaining stable evidence: category=prompt_injection, match=ignore previous instructions
	want := sha256hex("PS_001", "SKILL.md", "category=prompt_injection|match=ignore previous instructions")
	if got != want {
		t.Errorf("sorted fallback: got %s, want %s", got, want)
	}
}

func TestComputeFingerprint_EmptyEvidence(t *testing.T) {
	finding := document.ScanFinding{
		RuleID:   "QA_001",
		Severity: document.SeverityInfo,
		Evidence: nil,
	}
	got := fingerprint.ComputeFingerprint(finding)
	// nil evidence → empty file path and empty stable evidence
	want := sha256hex("QA_001", "", "")
	if got != want {
		t.Errorf("empty evidence: got %s, want %s", got, want)
	}
}

func TestComputeFingerprint_StableAcrossLineChanges(t *testing.T) {
	base := document.ScanFinding{
		RuleID:   "SEC_002",
		Severity: document.SeverityHigh,
		Evidence: map[string]any{
			"key":         "secret",
			"line_number": 10,
			"file":        "CLAUDE.md",
		},
	}
	moved := document.ScanFinding{
		RuleID:   "SEC_002",
		Severity: document.SeverityHigh,
		Evidence: map[string]any{
			"key":         "secret",
			"line_number": 99,
			"file":        "CLAUDE.md",
		},
	}
	if fingerprint.ComputeFingerprint(base) != fingerprint.ComputeFingerprint(moved) {
		t.Error("fingerprint changed when only line_number changed")
	}
}

func TestComputeFingerprint_ReturnsSHA256Hex(t *testing.T) {
	finding := document.ScanFinding{
		RuleID:   "SEC_001",
		Evidence: map[string]any{"snippet": "hello"},
	}
	got := fingerprint.ComputeFingerprint(finding)
	if len(got) != 64 {
		t.Errorf("expected 64-char hex digest, got len=%d: %s", len(got), got)
	}
	for _, c := range got {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("non-hex character in fingerprint: %c", c)
		}
	}
}

func TestComputeFingerprint_DifferentRulesDontCollide(t *testing.T) {
	f1 := document.ScanFinding{
		RuleID:   "SEC_001",
		Message:  "same message",
		Evidence: map[string]any{"snippet": "secret"},
	}
	f2 := document.ScanFinding{
		RuleID:   "SEC_002",
		Message:  "same message",
		Evidence: map[string]any{"snippet": "secret"},
	}
	fp1 := fingerprint.ComputeFingerprint(f1)
	fp2 := fingerprint.ComputeFingerprint(f2)
	if fp1 == fp2 {
		t.Error("different rule IDs should produce different fingerprints")
	}
}

func TestComputeFingerprint_DifferentSnippetsDontCollide(t *testing.T) {
	f1 := document.ScanFinding{
		RuleID:   "SEC_001",
		Evidence: map[string]any{"snippet": "secret_a"},
	}
	f2 := document.ScanFinding{
		RuleID:   "SEC_001",
		Evidence: map[string]any{"snippet": "secret_b"},
	}
	fp1 := fingerprint.ComputeFingerprint(f1)
	fp2 := fingerprint.ComputeFingerprint(f2)
	if fp1 == fp2 {
		t.Error("different snippets should produce different fingerprints")
	}
}

func TestComputeFingerprint_NilEvidence(t *testing.T) {
	f := document.ScanFinding{
		RuleID:   "SEC_001",
		Evidence: nil,
	}
	fp := fingerprint.ComputeFingerprint(f)
	if len(fp) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars", len(fp))
	}
}

func TestComputeFingerprint_LargeEvidenceMap(t *testing.T) {
	ev := make(map[string]any)
	for i := 0; i < 100; i++ {
		ev[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_%d", i)
	}
	f := document.ScanFinding{
		RuleID:   "SEC_001",
		Evidence: ev,
	}
	fp := fingerprint.ComputeFingerprint(f)
	if len(fp) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars", len(fp))
	}
}

func TestComputeFingerprint_Deterministic(t *testing.T) {
	f := document.ScanFinding{
		RuleID: "SEC_001",
		Evidence: map[string]any{
			"snippet": "abc",
			"key":     "val",
			"extra":   "data",
		},
	}
	fp1 := fingerprint.ComputeFingerprint(f)
	fp2 := fingerprint.ComputeFingerprint(f)
	if fp1 != fp2 {
		t.Error("same input must produce same fingerprint")
	}
}

func TestComputeFingerprint_IncludesFilePath(t *testing.T) {
	f1 := document.ScanFinding{
		RuleID:   "SEC_001",
		Evidence: map[string]any{"file": "a/SKILL.md", "snippet": "secret123"},
	}
	f2 := document.ScanFinding{
		RuleID:   "SEC_001",
		Evidence: map[string]any{"file": "b/SKILL.md", "snippet": "secret123"},
	}

	fp1 := fingerprint.ComputeFingerprint(f1)
	fp2 := fingerprint.ComputeFingerprint(f2)

	if fp1 == fp2 {
		t.Error("fingerprints should differ when file paths differ")
	}
}

func TestComputeFingerprint_SameFileProducesSameFingerprint(t *testing.T) {
	f1 := document.ScanFinding{
		RuleID:   "SEC_001",
		Evidence: map[string]any{"file": "SKILL.md", "snippet": "secret123"},
	}
	f2 := document.ScanFinding{
		RuleID:   "SEC_001",
		Evidence: map[string]any{"file": "SKILL.md", "snippet": "secret123"},
	}

	if fingerprint.ComputeFingerprint(f1) != fingerprint.ComputeFingerprint(f2) {
		t.Error("fingerprints should match for same file and evidence")
	}
}
