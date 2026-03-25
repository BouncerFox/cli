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
	want := sha256hex("SEC_001", "AKIAIOSFODNN7EXAMPLE")
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
	want := sha256hex("CFG_001", "allowed_tools")
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
	want := sha256hex("QA_002", "description")
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
	// Positional fields "line", "line_number", "file" excluded.
	// Remaining: category=prompt_injection, match=ignore previous instructions
	want := sha256hex("PS_001", "category=prompt_injection|match=ignore previous instructions")
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
	// empty sorted fallback → empty string component
	want := sha256hex("QA_001", "")
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
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex character in fingerprint: %c", c)
		}
	}
}
