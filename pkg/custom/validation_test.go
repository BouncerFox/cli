package custom

import (
	"strings"
	"testing"
)

func TestValidate_MinimalValid(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"type":  "content_contains",
			"value": "TODO",
		},
	}
	if err := Validate(rule); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidate_MissingID(t *testing.T) {
	rule := map[string]any{
		"severity": "warn",
		"match": map[string]any{
			"type":  "content_contains",
			"value": "TODO",
		},
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for missing id")
	}
	if !strings.Contains(err.Error(), "\"id\"") {
		t.Fatalf("error should mention id, got: %v", err)
	}
}

func TestValidate_MissingSeverity(t *testing.T) {
	rule := map[string]any{
		"id": "CUST_001",
		"match": map[string]any{
			"type":  "content_contains",
			"value": "TODO",
		},
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for missing severity")
	}
	if !strings.Contains(err.Error(), "severity") {
		t.Fatalf("error should mention severity, got: %v", err)
	}
}

func TestValidate_InvalidSeverity(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "extreme",
		"match": map[string]any{
			"type":  "content_contains",
			"value": "TODO",
		},
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
	if !strings.Contains(err.Error(), "extreme") {
		t.Fatalf("error should mention bad severity value, got: %v", err)
	}
}

func TestValidate_MissingMatch(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "warn",
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for missing match")
	}
	if !strings.Contains(err.Error(), "match") {
		t.Fatalf("error should mention match, got: %v", err)
	}
}

func TestValidate_InvalidIDFormat(t *testing.T) {
	cases := []string{
		"cust_001",   // lowercase
		"CUST001",    // no underscore
		"C_001",      // too few letters
		"ABCDEF_001", // too many letters
		"CUST_01",    // too few digits
		"CUST_0001",  // too many digits
		"",           // empty
	}
	for _, id := range cases {
		rule := map[string]any{
			"id":       id,
			"severity": "warn",
			"match": map[string]any{
				"type":  "content_contains",
				"value": "TODO",
			},
		}
		err := Validate(rule)
		if err == nil {
			t.Errorf("expected error for id %q, got nil", id)
		}
	}
}

func TestValidate_UnknownMatchType(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"type": "does_not_exist",
		},
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for unknown match type")
	}
	if !strings.Contains(err.Error(), "does_not_exist") {
		t.Fatalf("error should mention the bad type, got: %v", err)
	}
}

func TestValidate_InvalidRegexInLinePattern(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"type":    "line_pattern",
			"pattern": "[invalid",
		},
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
	if !strings.Contains(err.Error(), "regex") {
		t.Fatalf("error should mention regex, got: %v", err)
	}
}

func TestValidate_InvalidRegexInFieldMatches(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"type":    "field_matches",
			"field":   "name",
			"pattern": "(unclosed",
		},
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for invalid regex in field_matches")
	}
	if !strings.Contains(err.Error(), "regex") {
		t.Fatalf("error should mention regex, got: %v", err)
	}
}

func TestValidate_ValidComplexAllOf(t *testing.T) {
	rule := map[string]any{
		"id":       "SEC_002",
		"severity": "high",
		"match": map[string]any{
			"type": "all_of",
			"matches": []any{
				map[string]any{
					"type":  "content_contains",
					"value": "password",
				},
				map[string]any{
					"type":    "line_pattern",
					"pattern": `(?i)secret`,
				},
			},
		},
	}
	if err := Validate(rule); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidate_UnknownTopLevelKey(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"type":  "content_contains",
			"value": "TODO",
		},
		"bogus_key": "something",
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for unknown top-level key")
	}
	if !strings.Contains(err.Error(), "bogus_key") {
		t.Fatalf("error should mention the bad key, got: %v", err)
	}
}

func TestValidate_AllOptionalFields(t *testing.T) {
	rule := map[string]any{
		"id":          "CUST_001",
		"name":        "Check for TODOs",
		"description": "Finds TODO comments",
		"severity":    "info",
		"remediation": "Remove TODO comments before merging",
		"category":    "quality",
		"file_types":  []any{"skill_md", "claude_md"},
		"match": map[string]any{
			"type":  "content_contains",
			"value": "TODO",
		},
	}
	if err := Validate(rule); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidate_InvalidFileTypesNotList(t *testing.T) {
	rule := map[string]any{
		"id":         "CUST_001",
		"severity":   "warn",
		"file_types": "skill_md",
		"match": map[string]any{
			"type":  "content_contains",
			"value": "TODO",
		},
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for file_types not being a list")
	}
	if !strings.Contains(err.Error(), "file_types") {
		t.Fatalf("error should mention file_types, got: %v", err)
	}
}

func TestValidate_InvalidFileTypesElement(t *testing.T) {
	rule := map[string]any{
		"id":         "CUST_001",
		"severity":   "warn",
		"file_types": []any{"skill_md", 42},
		"match": map[string]any{
			"type":  "content_contains",
			"value": "TODO",
		},
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for non-string file_types element")
	}
}

func TestValidate_NotCombinator(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"type": "not",
			"match": map[string]any{
				"type":  "content_contains",
				"value": "required text",
			},
		},
	}
	if err := Validate(rule); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidate_PerFileType(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"type": "per_file_type",
			"file_types": map[string]any{
				"skill_md": map[string]any{
					"type":  "content_contains",
					"value": "## Parameters",
				},
				"claude_md": map[string]any{
					"type":    "line_pattern",
					"pattern": `^#\s+`,
				},
			},
		},
	}
	if err := Validate(rule); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidate_LegacyMultiKeyStyle(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"content_contains": "TODO",
			"field_exists":     "name",
		},
	}
	if err := Validate(rule); err != nil {
		t.Fatalf("expected no error for legacy multi-key style, got: %v", err)
	}
}

func TestValidate_LegacyUnknownKey(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"fake_primitive": "something",
		},
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for unknown legacy match key")
	}
	if !strings.Contains(err.Error(), "fake_primitive") {
		t.Fatalf("error should mention the bad key, got: %v", err)
	}
}

func TestValidate_InvalidRegexInLinePatterns(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"type": "line_patterns",
			"patterns": []any{
				"valid_pattern",
				"[invalid",
			},
		},
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for invalid regex in line_patterns")
	}
	if !strings.Contains(err.Error(), "regex") {
		t.Fatalf("error should mention regex, got: %v", err)
	}
}

func TestValidate_NestedCombinatorWithBadRegex(t *testing.T) {
	rule := map[string]any{
		"id":       "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"type": "any_of",
			"matches": []any{
				map[string]any{
					"type":    "line_pattern",
					"pattern": "[bad",
				},
			},
		},
	}
	err := Validate(rule)
	if err == nil {
		t.Fatal("expected error for bad regex nested in any_of")
	}
}

func TestValidate_CriticalSeverity(t *testing.T) {
	rule := map[string]any{
		"id":       "SEC_001",
		"severity": "critical",
		"match": map[string]any{
			"type":  "content_contains",
			"value": "secret",
		},
	}
	if err := Validate(rule); err != nil {
		t.Fatalf("expected no error for critical severity, got: %v", err)
	}
}
