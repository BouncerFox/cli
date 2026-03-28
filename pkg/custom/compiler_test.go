package custom_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/bouncerfox/cli/pkg/custom"
	"github.com/bouncerfox/cli/pkg/document"
)

// makeRule builds a minimal rule map for use in tests.
func makeRule(id, severity string, match map[string]any) map[string]any {
	return map[string]any{
		"id":          id,
		"name":        id + " name",
		"severity":    severity,
		"remediation": "fix it",
		"match":       match,
	}
}

func doc(fileType, content string, parsed map[string]any) *document.ConfigDocument {
	if parsed == nil {
		parsed = map[string]any{}
	}
	return &document.ConfigDocument{
		FileType: fileType,
		FilePath: "test/file.md",
		Content:  content,
		Parsed:   parsed,
	}
}

// ---------------------------------------------------------------------------
// Compile errors
// ---------------------------------------------------------------------------

func TestCompile_MissingMatch(t *testing.T) {
	_, err := custom.Compile(map[string]any{"id": "X001", "severity": "info"})
	if err == nil {
		t.Fatal("expected error for missing 'match'")
	}
}

func TestCompile_BadSeverity(t *testing.T) {
	_, err := custom.Compile(makeRule("X001", "banana", map[string]any{
		"type": "content_contains", "value": "x",
	}))
	if err == nil {
		t.Fatal("expected error for unknown severity")
	}
}

func TestCompile_BadRegex(t *testing.T) {
	_, err := custom.Compile(makeRule("X001", "info", map[string]any{
		"type": "line_pattern", "pattern": "[invalid",
	}))
	if err == nil {
		t.Fatal("expected error for bad regex")
	}
}

// ---------------------------------------------------------------------------
// line_pattern
// ---------------------------------------------------------------------------

func TestLinePattern_Match(t *testing.T) {
	fn := mustCompile(t, makeRule("LP001", "warn", map[string]any{
		"type": "line_pattern", "pattern": `\bsecret\b`,
	}))
	d := doc("claude_md", "this is fine\nmy secret is here\nok", nil)
	findings := fn(d)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Evidence["line"] != 2 {
		t.Errorf("expected line 2, got %v", findings[0].Evidence["line"])
	}
	if findings[0].Severity != document.SeverityWarn {
		t.Errorf("expected warn severity")
	}
}

func TestLinePattern_NoMatch(t *testing.T) {
	fn := mustCompile(t, makeRule("LP001", "info", map[string]any{
		"type": "line_pattern", "pattern": `\bsecret\b`,
	}))
	d := doc("claude_md", "nothing to see here", nil)
	if len(fn(d)) != 0 {
		t.Fatal("expected no findings")
	}
}

func TestLinePattern_MultipleMatches(t *testing.T) {
	fn := mustCompile(t, makeRule("LP001", "info", map[string]any{
		"type": "line_pattern", "pattern": `TODO`,
	}))
	d := doc("claude_md", "TODO: fix this\nTODO: fix that\nclean line", nil)
	findings := fn(d)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestLinePattern_SkipCodeBlocks(t *testing.T) {
	fn := mustCompile(t, makeRule("LP001", "info", map[string]any{
		"type": "line_pattern", "pattern": `TODO`, "skip_code_blocks": true,
	}))
	d := doc("claude_md", "TODO: outside\nTODO: inside", map[string]any{
		"code_block_lines": map[int]struct{}{2: {}},
	})
	findings := fn(d)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (code block skipped), got %d", len(findings))
	}
	if findings[0].Evidence["line"] != 1 {
		t.Errorf("expected line 1")
	}
}

// ---------------------------------------------------------------------------
// line_patterns
// ---------------------------------------------------------------------------

func TestLinePatterns_Match(t *testing.T) {
	fn := mustCompile(t, makeRule("LPS001", "info", map[string]any{
		"type": "line_patterns",
		"patterns": []any{
			map[string]any{"pattern": `foo`},
			map[string]any{"pattern": `bar`},
		},
	}))
	d := doc("skill_md", "line with foo\nline with bar\nclean", nil)
	findings := fn(d)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestLinePatterns_OneFindingPerLine(t *testing.T) {
	fn := mustCompile(t, makeRule("LPS001", "info", map[string]any{
		"type": "line_patterns",
		"patterns": []any{
			map[string]any{"pattern": `foo`},
			map[string]any{"pattern": `foo`},
		},
	}))
	// Line matches both patterns — should still be only 1 finding
	d := doc("skill_md", "foo on this line", nil)
	if len(fn(d)) != 1 {
		t.Fatal("expected exactly 1 finding per line even when multiple patterns match")
	}
}

// ---------------------------------------------------------------------------
// content_contains / content_not_contains
// ---------------------------------------------------------------------------

func TestContentContains_Match(t *testing.T) {
	fn := mustCompile(t, makeRule("CC001", "info", map[string]any{
		"type": "content_contains", "value": "forbidden",
	}))
	if len(fn(doc("skill_md", "this has forbidden text", nil))) != 1 {
		t.Fatal("expected match")
	}
	if len(fn(doc("skill_md", "this is clean", nil))) != 0 {
		t.Fatal("expected no match")
	}
}

func TestContentNotContains_Match(t *testing.T) {
	fn := mustCompile(t, makeRule("CNC001", "warn", map[string]any{
		"type": "content_not_contains", "value": "required_keyword",
	}))
	if len(fn(doc("skill_md", "no required_keyword here is wrong", nil))) != 0 {
		t.Fatal("expected no finding when keyword present")
	}
	if len(fn(doc("skill_md", "no keyword at all", nil))) != 1 {
		t.Fatal("expected finding when keyword absent")
	}
}

// ---------------------------------------------------------------------------
// field_equals
// ---------------------------------------------------------------------------

func TestFieldEquals_Match(t *testing.T) {
	fn := mustCompile(t, makeRule("FE001", "high", map[string]any{
		"type": "field_equals", "field": "frontmatter.model", "value": "gpt-4",
	}))
	d := doc("skill_md", "", map[string]any{
		"frontmatter": map[string]any{"model": "gpt-4"},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for matching field")
	}
}

func TestFieldEquals_NoMatch(t *testing.T) {
	fn := mustCompile(t, makeRule("FE001", "high", map[string]any{
		"type": "field_equals", "field": "frontmatter.model", "value": "gpt-4",
	}))
	d := doc("skill_md", "", map[string]any{
		"frontmatter": map[string]any{"model": "claude-3"},
	})
	if len(fn(d)) != 0 {
		t.Fatal("expected no finding for non-matching field")
	}
}

func TestFieldEquals_MissingField(t *testing.T) {
	fn := mustCompile(t, makeRule("FE001", "info", map[string]any{
		"type": "field_equals", "field": "frontmatter.model", "value": "gpt-4",
	}))
	if len(fn(doc("skill_md", "", nil))) != 0 {
		t.Fatal("expected no finding for missing field")
	}
}

// ---------------------------------------------------------------------------
// field_exists / field_missing
// ---------------------------------------------------------------------------

func TestFieldExists_Present(t *testing.T) {
	fn := mustCompile(t, makeRule("FEX001", "info", map[string]any{
		"type": "field_exists", "field": "frontmatter.title",
	}))
	d := doc("skill_md", "", map[string]any{
		"frontmatter": map[string]any{"title": "My Skill"},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for present field")
	}
}

func TestFieldExists_Missing(t *testing.T) {
	fn := mustCompile(t, makeRule("FEX001", "info", map[string]any{
		"type": "field_exists", "field": "frontmatter.title",
	}))
	if len(fn(doc("skill_md", "", nil))) != 0 {
		t.Fatal("expected no finding for missing field")
	}
}

func TestFieldExists_Empty(t *testing.T) {
	fn := mustCompile(t, makeRule("FEX001", "info", map[string]any{
		"type": "field_exists", "field": "frontmatter.title",
	}))
	d := doc("skill_md", "", map[string]any{
		"frontmatter": map[string]any{"title": ""},
	})
	if len(fn(d)) != 0 {
		t.Fatal("expected no finding for empty string field")
	}
}

func TestFieldMissing_Missing(t *testing.T) {
	fn := mustCompile(t, makeRule("FM001", "warn", map[string]any{
		"type": "field_missing", "field": "frontmatter.description",
	}))
	if len(fn(doc("skill_md", "", nil))) != 1 {
		t.Fatal("expected finding for missing field")
	}
}

func TestFieldMissing_Present(t *testing.T) {
	fn := mustCompile(t, makeRule("FM001", "warn", map[string]any{
		"type": "field_missing", "field": "frontmatter.description",
	}))
	d := doc("skill_md", "", map[string]any{
		"frontmatter": map[string]any{"description": "something"},
	})
	if len(fn(d)) != 0 {
		t.Fatal("expected no finding for present field")
	}
}

// ---------------------------------------------------------------------------
// field_in / field_not_in
// ---------------------------------------------------------------------------

func TestFieldIn_Scalar(t *testing.T) {
	fn := mustCompile(t, makeRule("FIN001", "info", map[string]any{
		"type":   "field_in",
		"field":  "settings.level",
		"values": []any{"low", "medium"},
	}))
	d := doc("skill_md", "", map[string]any{
		"settings": map[string]any{"level": "medium"},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding when value in set")
	}
}

func TestFieldIn_List(t *testing.T) {
	fn := mustCompile(t, makeRule("FIN001", "info", map[string]any{
		"type":   "field_in",
		"field":  "tags",
		"values": []any{"deprecated"},
	}))
	d := doc("skill_md", "", map[string]any{
		"tags": []any{"stable", "deprecated"},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding when list contains value in set")
	}
}

func TestFieldNotIn_Match(t *testing.T) {
	fn := mustCompile(t, makeRule("FNIN001", "info", map[string]any{
		"type":   "field_not_in",
		"field":  "settings.level",
		"values": []any{"low", "medium", "high"},
	}))
	d := doc("skill_md", "", map[string]any{
		"settings": map[string]any{"level": "extreme"},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding when value NOT in allowed set")
	}
}

// ---------------------------------------------------------------------------
// field_matches
// ---------------------------------------------------------------------------

func TestFieldMatches_Match(t *testing.T) {
	fn := mustCompile(t, makeRule("FM001", "info", map[string]any{
		"type": "field_matches", "field": "frontmatter.version", "pattern": `^\d+\.\d+`,
	}))
	d := doc("skill_md", "", map[string]any{
		"frontmatter": map[string]any{"version": "1.2.3"},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for matching pattern")
	}
}

func TestFieldMatches_Negate(t *testing.T) {
	fn := mustCompile(t, makeRule("FM002", "info", map[string]any{
		"type": "field_matches", "field": "frontmatter.version",
		"pattern": `^\d+\.\d+`, "negate": true,
	}))
	d := doc("skill_md", "", map[string]any{
		"frontmatter": map[string]any{"version": "not-a-version"},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding when negated pattern doesn't match")
	}
}

// ---------------------------------------------------------------------------
// collection_any / collection_none
// ---------------------------------------------------------------------------

func TestCollectionAny_Equals(t *testing.T) {
	fn := mustCompile(t, makeRule("CA001", "info", map[string]any{
		"type":  "collection_any",
		"field": "servers",
		"match": map[string]any{"equals": "bad-server"},
	}))
	d := doc("mcp_json", "", map[string]any{
		"servers": []any{"good-server", "bad-server"},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for collection containing matching item")
	}
}

func TestCollectionAny_NoMatch(t *testing.T) {
	fn := mustCompile(t, makeRule("CA001", "info", map[string]any{
		"type":  "collection_any",
		"field": "servers",
		"match": map[string]any{"equals": "bad-server"},
	}))
	d := doc("mcp_json", "", map[string]any{
		"servers": []any{"good-server", "another-server"},
	})
	if len(fn(d)) != 0 {
		t.Fatal("expected no finding")
	}
}

func TestCollectionAny_DictKeyMatches(t *testing.T) {
	fn := mustCompile(t, makeRule("CA001", "info", map[string]any{
		"type":  "collection_any",
		"field": "mcpServers",
		"match": map[string]any{
			"field_equals": map[string]any{"field": "_key", "value": "badServer"},
		},
	}))
	d := doc("mcp_json", "", map[string]any{
		"mcpServers": map[string]any{
			"badServer":  map[string]any{"url": "http://evil"},
			"goodServer": map[string]any{"url": "http://ok"},
		},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for matching dict key")
	}
}

func TestCollectionNone_ViolationFound(t *testing.T) {
	fn := mustCompile(t, makeRule("CN001", "warn", map[string]any{
		"type":  "collection_none",
		"field": "tools",
		"match": map[string]any{"equals": "dangerous_tool"},
	}))
	d := doc("skill_md", "", map[string]any{
		"tools": []any{"safe_tool", "dangerous_tool"},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding when prohibited item found")
	}
}

func TestCollectionNone_NoViolation(t *testing.T) {
	fn := mustCompile(t, makeRule("CN001", "warn", map[string]any{
		"type":  "collection_none",
		"field": "tools",
		"match": map[string]any{"equals": "dangerous_tool"},
	}))
	d := doc("skill_md", "", map[string]any{
		"tools": []any{"safe_tool"},
	})
	if len(fn(d)) != 0 {
		t.Fatal("expected no finding")
	}
}

func TestCollectionAny_MatchesRegex(t *testing.T) {
	fn := mustCompile(t, makeRule("CA002", "info", map[string]any{
		"type":  "collection_any",
		"field": "items",
		"match": map[string]any{"matches": `^secret_`},
	}))
	d := doc("skill_md", "", map[string]any{
		"items": []any{"normal", "secret_key"},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for regex match")
	}
}

func TestCollectionAny_FieldStartsWith(t *testing.T) {
	fn := mustCompile(t, makeRule("CA003", "info", map[string]any{
		"type":  "collection_any",
		"field": "servers",
		"match": map[string]any{
			"field_starts_with": map[string]any{"field": "url", "value": "http://"},
		},
	}))
	d := doc("mcp_json", "", map[string]any{
		"servers": []any{
			map[string]any{"url": "http://insecure.example.com"},
		},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for field_starts_with match")
	}
}

func TestCollectionAny_HasField(t *testing.T) {
	fn := mustCompile(t, makeRule("CA004", "info", map[string]any{
		"type":  "collection_any",
		"field": "entries",
		"match": map[string]any{"has_field": "secret"},
	}))
	d := doc("mcp_json", "", map[string]any{
		"entries": []any{
			map[string]any{"name": "safe"},
			map[string]any{"name": "bad", "secret": "value"},
		},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for item with 'secret' field")
	}
}

// ---------------------------------------------------------------------------
// min_length / max_length / max_size_bytes
// ---------------------------------------------------------------------------

func TestMinLength_TooShort(t *testing.T) {
	fn := mustCompile(t, makeRule("ML001", "info", map[string]any{
		"type": "min_length", "field": "frontmatter.description", "value": 50,
	}))
	d := doc("skill_md", "", map[string]any{
		"frontmatter": map[string]any{"description": "short"},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for too-short field")
	}
}

func TestMinLength_LongEnough(t *testing.T) {
	fn := mustCompile(t, makeRule("ML001", "info", map[string]any{
		"type": "min_length", "field": "frontmatter.description", "value": 5,
	}))
	d := doc("skill_md", "", map[string]any{
		"frontmatter": map[string]any{"description": "long enough description"},
	})
	if len(fn(d)) != 0 {
		t.Fatal("expected no finding when length meets minimum")
	}
}

func TestMaxLength_TooLong(t *testing.T) {
	fn := mustCompile(t, makeRule("MXLEN001", "info", map[string]any{
		"type": "max_length", "field": "frontmatter.name", "value": 10,
	}))
	d := doc("skill_md", "", map[string]any{
		"frontmatter": map[string]any{"name": "this is way too long for the limit"},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for too-long field")
	}
}

func TestMaxSizeBytes_TooBig(t *testing.T) {
	fn := mustCompile(t, makeRule("MSB001", "info", map[string]any{
		"type": "max_size_bytes", "value": 10,
	}))
	d := doc("skill_md", strings.Repeat("x", 100), nil)
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for oversized file")
	}
}

func TestMaxSizeBytes_OK(t *testing.T) {
	fn := mustCompile(t, makeRule("MSB001", "info", map[string]any{
		"type": "max_size_bytes", "value": 1000,
	}))
	d := doc("skill_md", "small content", nil)
	if len(fn(d)) != 0 {
		t.Fatal("expected no finding for small file")
	}
}

// ---------------------------------------------------------------------------
// Boolean combinators
// ---------------------------------------------------------------------------

func TestAllOf_BothMatch(t *testing.T) {
	fn := mustCompile(t, makeRule("AO001", "info", map[string]any{
		"type": "all_of",
		"matches": []any{
			map[string]any{"type": "content_contains", "value": "foo"},
			map[string]any{"type": "content_contains", "value": "bar"},
		},
	}))
	d := doc("skill_md", "has foo and bar", nil)
	if len(fn(d)) == 0 {
		t.Fatal("expected findings when all conditions match")
	}
}

func TestAllOf_OneMisses(t *testing.T) {
	fn := mustCompile(t, makeRule("AO001", "info", map[string]any{
		"type": "all_of",
		"matches": []any{
			map[string]any{"type": "content_contains", "value": "foo"},
			map[string]any{"type": "content_contains", "value": "missing"},
		},
	}))
	d := doc("skill_md", "has foo only", nil)
	if len(fn(d)) != 0 {
		t.Fatal("expected no findings when one condition fails")
	}
}

func TestAnyOf_FirstMatches(t *testing.T) {
	fn := mustCompile(t, makeRule("ANYOF001", "info", map[string]any{
		"type": "any_of",
		"matches": []any{
			map[string]any{"type": "content_contains", "value": "foo"},
			map[string]any{"type": "content_contains", "value": "bar"},
		},
	}))
	d := doc("skill_md", "has only foo", nil)
	if len(fn(d)) == 0 {
		t.Fatal("expected finding when any condition matches")
	}
}

func TestAnyOf_NoneMatch(t *testing.T) {
	fn := mustCompile(t, makeRule("ANYOF001", "info", map[string]any{
		"type": "any_of",
		"matches": []any{
			map[string]any{"type": "content_contains", "value": "foo"},
			map[string]any{"type": "content_contains", "value": "bar"},
		},
	}))
	d := doc("skill_md", "has neither", nil)
	if len(fn(d)) != 0 {
		t.Fatal("expected no finding when nothing matches")
	}
}

func TestNot_InnerProducesNothing(t *testing.T) {
	fn := mustCompile(t, makeRule("NOT001", "warn", map[string]any{
		"type":  "not",
		"match": map[string]any{"type": "content_contains", "value": "required"},
	}))
	d := doc("skill_md", "no mandatory keyword here", nil)
	if len(fn(d)) != 1 {
		t.Fatal("expected finding when inner check finds nothing")
	}
}

func TestNot_InnerProducesFindings(t *testing.T) {
	fn := mustCompile(t, makeRule("NOT001", "warn", map[string]any{
		"type":  "not",
		"match": map[string]any{"type": "content_contains", "value": "required"},
	}))
	d := doc("skill_md", "has required keyword", nil)
	if len(fn(d)) != 0 {
		t.Fatal("expected no finding when inner check fires")
	}
}

// ---------------------------------------------------------------------------
// per_file_type
// ---------------------------------------------------------------------------

func TestPerFileType_RightBranch(t *testing.T) {
	fn := mustCompile(t, makeRule("PFT001", "info", map[string]any{
		"type": "per_file_type",
		"file_types": map[string]any{
			"skill_md": map[string]any{
				"type": "content_contains", "value": "skill-specific",
			},
			"claude_md": map[string]any{
				"type": "content_contains", "value": "claude-specific",
			},
		},
	}))
	skillDoc := doc("skill_md", "has skill-specific content", nil)
	claudeDoc := doc("claude_md", "has claude-specific content", nil)
	wrongDoc := doc("skill_md", "has claude-specific content", nil)

	if len(fn(skillDoc)) != 1 {
		t.Fatal("expected finding in skill_md branch")
	}
	if len(fn(claudeDoc)) != 1 {
		t.Fatal("expected finding in claude_md branch")
	}
	if len(fn(wrongDoc)) != 0 {
		t.Fatal("expected no finding for wrong file type")
	}
}

func TestPerFileType_UnknownType(t *testing.T) {
	fn := mustCompile(t, makeRule("PFT001", "info", map[string]any{
		"type": "per_file_type",
		"file_types": map[string]any{
			"skill_md": map[string]any{
				"type": "content_contains", "value": "anything",
			},
		},
	}))
	d := doc("mcp_json", "anything", nil)
	if len(fn(d)) != 0 {
		t.Fatal("expected no finding for unmatched file type")
	}
}

// ---------------------------------------------------------------------------
// Finding metadata
// ---------------------------------------------------------------------------

func TestFindingMetadata(t *testing.T) {
	fn := mustCompile(t, makeRule("META001", "critical", map[string]any{
		"type": "content_contains", "value": "danger",
	}))
	d := doc("skill_md", "danger here", nil)
	findings := fn(d)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "META001" {
		t.Errorf("expected rule id META001, got %s", f.RuleID)
	}
	if f.Severity != document.SeverityCritical {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
	if !strings.Contains(f.Message, "custom rule") {
		t.Errorf("expected message to contain 'custom rule', got %q", f.Message)
	}
	if f.Remediation != "fix it" {
		t.Errorf("expected remediation 'fix it', got %q", f.Remediation)
	}
	if f.Evidence["file"] != "test/file.md" {
		t.Errorf("expected evidence file to be set")
	}
	if f.Evidence["line"].(int) < 1 {
		t.Errorf("expected evidence line >= 1")
	}
}

func TestFindingLineNumber_LinePattern(t *testing.T) {
	fn := mustCompile(t, makeRule("LN001", "info", map[string]any{
		"type": "line_pattern", "pattern": `match_me`,
	}))
	d := doc("skill_md", "line1\nline2\nmatch_me here\nline4", nil)
	findings := fn(d)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if findings[0].Evidence["line"] != 3 {
		t.Errorf("expected line 3, got %v", findings[0].Evidence["line"])
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestResolveFieldPath_Deep(t *testing.T) {
	// Test deeply nested path resolution via field_equals
	fn := mustCompile(t, makeRule("DEEP001", "info", map[string]any{
		"type":  "field_equals",
		"field": "a.b.c",
		"value": "deep",
	}))
	d := doc("skill_md", "", map[string]any{
		"a": map[string]any{
			"b": map[string]any{"c": "deep"},
		},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for deep path resolution")
	}
}

func TestResolveFieldPath_PartialMissing(t *testing.T) {
	fn := mustCompile(t, makeRule("DEEP001", "info", map[string]any{
		"type":  "field_equals",
		"field": "a.b.c",
		"value": "deep",
	}))
	// "a" exists but "a.b" does not
	d := doc("skill_md", "", map[string]any{
		"a": map[string]any{"x": "y"},
	})
	if len(fn(d)) != 0 {
		t.Fatal("expected no finding for partially missing path")
	}
}

// ---------------------------------------------------------------------------
// Unknown primitive — no-op
// ---------------------------------------------------------------------------

func TestUnknownPrimitive_Noop(t *testing.T) {
	fn := mustCompile(t, makeRule("UNK001", "info", map[string]any{
		"type": "not_a_real_primitive",
	}))
	d := doc("skill_md", "anything", nil)
	if len(fn(d)) != 0 {
		t.Fatal("unknown primitive should be a no-op")
	}
}

// ---------------------------------------------------------------------------
// Severity parsing
// ---------------------------------------------------------------------------

func TestSeverityLevels(t *testing.T) {
	cases := []struct {
		sev      string
		expected document.FindingSeverity
	}{
		{"critical", document.SeverityCritical},
		{"high", document.SeverityHigh},
		{"warn", document.SeverityWarn},
		{"warning", document.SeverityWarn},
		{"info", document.SeverityInfo},
		{"", document.SeverityInfo},
	}
	for _, tc := range cases {
		fn := mustCompile(t, makeRule("SEV001", tc.sev, map[string]any{
			"type": "content_contains", "value": "x",
		}))
		d := doc("skill_md", "x", nil)
		findings := fn(d)
		if len(findings) != 1 {
			t.Fatalf("sev=%q: expected 1 finding", tc.sev)
		}
		if findings[0].Severity != tc.expected {
			t.Errorf("sev=%q: expected %s, got %s", tc.sev, tc.expected, findings[0].Severity)
		}
	}
}

// ---------------------------------------------------------------------------
// collection field_in / field_not_in conditions
// ---------------------------------------------------------------------------

func TestCollectionAny_FieldIn(t *testing.T) {
	fn := mustCompile(t, makeRule("CFI001", "info", map[string]any{
		"type":  "collection_any",
		"field": "servers",
		"match": map[string]any{
			"field_in": map[string]any{
				"field":  "_key",
				"values": []any{"bad1", "bad2"},
			},
		},
	}))
	d := doc("mcp_json", "", map[string]any{
		"servers": map[string]any{
			"bad1": map[string]any{},
			"ok":   map[string]any{},
		},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for key in disallowed set")
	}
}

func TestCollectionAny_FieldNotIn(t *testing.T) {
	fn := mustCompile(t, makeRule("CFNI001", "info", map[string]any{
		"type":  "collection_any",
		"field": "servers",
		"match": map[string]any{
			"field_not_in": map[string]any{
				"field":  "type",
				"values": []any{"allowed"},
			},
		},
	}))
	d := doc("mcp_json", "", map[string]any{
		"servers": []any{
			map[string]any{"type": "disallowed"},
		},
	})
	if len(fn(d)) != 1 {
		t.Fatal("expected finding for field value not in allowed set")
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func mustCompile(t *testing.T, rule map[string]any) custom.CheckFn {
	t.Helper()
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	return fn
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

func TestCollectionAny_IterationLimit(t *testing.T) {
	bigMap := make(map[string]any, 1100)
	for i := 0; i < 1100; i++ {
		bigMap[fmt.Sprintf("key_%d", i)] = "val"
	}
	rule := makeRule("X001", "info", map[string]any{
		"type":  "collection_any",
		"field": "items",
		"match": map[string]any{"equals": "val"},
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	d := doc("skill_md", "", map[string]any{"items": bigMap})
	findings := fn(d)
	if len(findings) == 0 {
		t.Error("expected a finding from collection_any on large map")
	}
}

func TestLinePattern_EmptyPattern(t *testing.T) {
	rule := makeRule("X001", "info", map[string]any{
		"type": "line_pattern", "pattern": "",
	})
	_, err := custom.Compile(rule)
	if err != nil {
		t.Logf("empty pattern returned error (acceptable): %v", err)
		return
	}
}

func TestLinePatterns_EmptyList(t *testing.T) {
	rule := makeRule("X001", "info", map[string]any{
		"type": "line_patterns", "patterns": []any{},
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Logf("empty patterns list returned error (acceptable): %v", err)
		return
	}
	d := doc("skill_md", "some content\n", nil)
	findings := fn(d)
	if len(findings) != 0 {
		t.Error("empty patterns list should produce no findings")
	}
}

func TestContentContains_EmptyValue(t *testing.T) {
	rule := makeRule("X001", "info", map[string]any{
		"type": "content_contains", "value": "",
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Logf("empty value returned error (acceptable): %v", err)
		return
	}
	d := doc("skill_md", "some content\n", nil)
	findings := fn(d)
	if len(findings) == 0 {
		t.Error("expected finding for empty content_contains value")
	}
}

func TestCollectionNone_EmptyCollection(t *testing.T) {
	rule := makeRule("X001", "info", map[string]any{
		"type": "collection_none", "field": "items",
		"match": map[string]any{"equals": "bad"},
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	d := doc("skill_md", "", map[string]any{})
	findings := fn(d)
	_ = findings // either outcome is valid, just don't panic
}

func TestFieldResolution_DeeplyNested(t *testing.T) {
	rule := makeRule("X001", "info", map[string]any{
		"type": "field_equals", "field": "a.b.c.d.e", "value": "deep",
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}

	parsed := map[string]any{
		"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": map[string]any{"e": "deep"}}}},
	}
	d := doc("skill_md", "", parsed)
	findings := fn(d)
	if len(findings) == 0 {
		t.Error("expected finding for deeply nested field match")
	}

	parsed2 := map[string]any{"a": map[string]any{"b": "not-a-map"}}
	d2 := doc("skill_md", "", parsed2)
	findings2 := fn(d2)
	if len(findings2) != 0 {
		t.Error("broken path should produce no findings")
	}
}

// ---------------------------------------------------------------------------
// Hardening tests
// ---------------------------------------------------------------------------

func TestCompile_NestingDepthLimit(t *testing.T) {
	inner := map[string]any{
		"type":  "content_contains",
		"value": "x",
	}
	for i := 0; i < 15; i++ {
		inner = map[string]any{
			"type":    "all_of",
			"matches": []any{inner},
		}
	}
	rule := makeRule("CUST_001", "warn", inner)
	_, err := custom.Compile(rule)
	if err == nil {
		t.Error("expected error for deeply nested match (exceeds depth limit)")
	}
}

func TestCompile_RegexSizeLimit(t *testing.T) {
	hugePattern := strings.Repeat("a", 10_000)
	rule := makeRule("CUST_001", "warn", map[string]any{
		"type":    "line_pattern",
		"pattern": hugePattern,
	})
	_, err := custom.Compile(rule)
	if err == nil {
		t.Error("expected error for oversized regex pattern")
	}
}
