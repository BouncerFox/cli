package parser

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func readFixture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", path, err)
	}
	return string(data)
}

func TestParseFrontmatterMD_Basic(t *testing.T) {
	content := readFixture(t, "../../testdata/skills/basic.md")
	doc := ParseFrontmatterMD("skill_md", ".claude/skills/my-skill/SKILL.md", content)

	if doc.FileType != "skill_md" {
		t.Errorf("FileType = %q, want skill_md", doc.FileType)
	}

	fm, ok := doc.Parsed["frontmatter"].(map[string]any)
	if !ok {
		t.Fatal("frontmatter not found or wrong type")
	}
	if fm["name"] != "my-skill" {
		t.Errorf("name = %v, want my-skill", fm["name"])
	}
	if fm["description"] != "A test skill for scanning" {
		t.Errorf("description = %v, want 'A test skill for scanning'", fm["description"])
	}
	if fm["model"] != "sonnet" {
		t.Errorf("model = %v, want sonnet", fm["model"])
	}

	// Check frontmatter_lines
	fmLines, ok := doc.Parsed["frontmatter_lines"].(map[string]int)
	if !ok {
		t.Fatal("frontmatter_lines not found or wrong type")
	}
	if fmLines["name"] != 2 {
		t.Errorf("frontmatter_lines[name] = %d, want 2", fmLines["name"])
	}

	// Check body doesn't contain frontmatter
	body := doc.Parsed["body"].(string)
	if body == "" {
		t.Error("body is empty")
	}
	if len(body) >= len(content) {
		t.Error("body should be shorter than full content (frontmatter stripped)")
	}

	// body_start_line
	bsl := doc.Parsed["body_start_line"].(int)
	if bsl < 2 {
		t.Errorf("body_start_line = %d, want >= 2", bsl)
	}

	// code_block_lines should exist
	cbl := doc.Parsed["code_block_lines"].(map[int]bool)
	if len(cbl) == 0 {
		t.Error("code_block_lines should not be empty (fixture has a code block)")
	}

	// content_code_block_lines should exist
	ccbl := doc.Parsed["content_code_block_lines"].(map[int]bool)
	if len(ccbl) == 0 {
		t.Error("content_code_block_lines should not be empty")
	}

	// content_hash should be non-empty
	if doc.ContentHash == "" {
		t.Error("ContentHash is empty")
	}
}

func TestParseFrontmatterMD_NoFrontmatter(t *testing.T) {
	content := readFixture(t, "../../testdata/skills/no-frontmatter.md")
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)

	fm := doc.Parsed["frontmatter"].(map[string]any)
	if len(fm) != 0 {
		t.Errorf("frontmatter should be empty, got %v", fm)
	}

	body := doc.Parsed["body"].(string)
	if body != doc.Content {
		t.Error("body should equal content when no frontmatter")
	}

	bsl := doc.Parsed["body_start_line"].(int)
	if bsl != 1 {
		t.Errorf("body_start_line = %d, want 1", bsl)
	}
}

func TestParseFrontmatterMD_YAMLBomb(t *testing.T) {
	content := readFixture(t, "../../testdata/skills/yaml-bomb.md")
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)

	parseErr, _ := doc.Parsed["_parse_error"].(bool)
	if !parseErr {
		t.Error("expected _parse_error = true for YAML bomb")
	}
	reason, _ := doc.Parsed["_reason"].(string)
	if reason != "yaml_anchors" {
		t.Errorf("_reason = %q, want yaml_anchors", reason)
	}
}

func TestParseFrontmatterMD_BinaryContent(t *testing.T) {
	content := "---\nname: test\n---\nbody\x00with null"
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)

	parseErr, _ := doc.Parsed["_parse_error"].(bool)
	if !parseErr {
		t.Error("expected _parse_error for binary content")
	}
	reason, _ := doc.Parsed["_reason"].(string)
	if reason != "binary_content" {
		t.Errorf("_reason = %q, want binary_content", reason)
	}
}

func TestParseFrontmatterMD_OversizedContent(t *testing.T) {
	huge := "---\nname: test\n---\n" + strings.Repeat("A", MaxContentSize)
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", huge)
	if doc.Parsed["_parse_error"] != true {
		t.Error("expected parse error for oversized content")
	}
	reason, _ := doc.Parsed["_reason"].(string)
	if reason != "content_too_large" {
		t.Errorf("expected reason content_too_large, got %q", reason)
	}
}

func TestParseClaudeMD_ContentAtLimit(t *testing.T) {
	doc := ParseClaudeMD("CLAUDE.md", strings.Repeat("A", MaxContentSize))
	if doc.Parsed["_parse_error"] == true {
		t.Errorf("content at the 1 MB limit should be accepted: %v", doc.Parsed)
	}
}

func TestParseFrontmatterMD_EmptyFrontmatter(t *testing.T) {
	content := "---\n---\nBody here"
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)
	if doc == nil {
		t.Fatal("expected non-nil doc for empty frontmatter")
	}
	// Empty frontmatter block is parsed as valid (empty map)
	fm, _ := doc.Parsed["frontmatter"].(map[string]any)
	if fm == nil {
		t.Error("expected non-nil frontmatter map")
	}
}

func TestParseFrontmatterMD_MalformedYAML(t *testing.T) {
	content := "---\nname: [unclosed\n---\nBody"
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)
	if doc.Parsed["_parse_error"] != true {
		t.Error("expected parse error for malformed YAML")
	}
	if reason, _ := doc.Parsed["_reason"].(string); reason != "invalid_yaml" {
		t.Errorf("_reason = %q, want invalid_yaml", reason)
	}
}

func TestParseFrontmatterMD_YAMLMergeKey(t *testing.T) {
	content := "---\nbase: &base\n  key: value\nmerged:\n  <<: *base\n---\nBody"
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)
	if doc.Parsed["_parse_error"] != true {
		t.Error("expected parse error for YAML merge key (uses anchors)")
	}
}

func TestParseFrontmatterMD_RejectsAdversarialYAMLReferences(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		line int
	}{
		{
			name: "sequence anchor and alias",
			yaml: "items:\n  - &defaults\n    key: value\n  - *defaults",
			line: 3,
		},
		{
			name: "flow anchor and alias",
			yaml: "items: [&item value, *item]",
			line: 2,
		},
		{
			name: "hyphenated anchor with merge alias",
			yaml: "base-config: &base\n  key: value\nmerged:\n  <<: *base",
			line: 2,
		},
		{
			name: "merge key with inline mapping",
			yaml: "merged:\n  <<: {key: value}",
			line: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := "---\n" + tt.yaml + "\n---\nBody"
			doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)
			if doc.Parsed["_parse_error"] != true {
				t.Fatal("expected YAML reference to be rejected")
			}
			if reason, _ := doc.Parsed["_reason"].(string); reason != "yaml_anchors" {
				t.Errorf("_reason = %q, want yaml_anchors", reason)
			}
			if line, _ := doc.Parsed["_rejection_line"].(int); line != tt.line {
				t.Errorf("_rejection_line = %d, want %d", line, tt.line)
			}
		})
	}
}

func TestParseFrontmatterMD_ReferenceParseErrorsUseSecurityReason(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{name: "undefined alias", yaml: "value: *missing"},
		{name: "self-referential anchor", yaml: "value: &self\n  nested: *self"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := ParseFrontmatterMD("skill_md", "SKILL.md", "---\n"+tt.yaml+"\n---\nBody")
			if doc.Parsed["_parse_error"] != true {
				t.Fatal("expected YAML reference to be rejected")
			}
			if reason, _ := doc.Parsed["_reason"].(string); reason != RejectionReasonYAMLReferences {
				t.Errorf("_reason = %q, want %q", reason, RejectionReasonYAMLReferences)
			}
		})
	}
}

func TestParseFrontmatterMD_YAMLReferenceSyntaxInsideScalarIsAllowed(t *testing.T) {
	content := "---\nname: example\n\"<<\": literal key\ndescription: |\n  key: &literal\n  alias: *literal\n---\nBody"
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)
	if doc.Parsed["_parse_error"] == true {
		t.Errorf("reference-like scalar text must not be rejected: %v", doc.Parsed)
	}
}

func TestParseFrontmatterMD_DeepNestedYAML(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("---\n")
	for i := 0; i < 50; i++ {
		sb.WriteString(strings.Repeat("  ", i))
		fmt.Fprintf(&sb, "level%d:\n", i)
	}
	sb.WriteString(strings.Repeat("  ", 50))
	sb.WriteString("value: deep\n")
	sb.WriteString("---\nBody")
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", sb.String())
	if doc == nil {
		t.Fatal("expected non-nil doc")
	}
}

func TestParseFrontmatterMD_InvalidUTF8(t *testing.T) {
	content := "---\nname: test\xff\xfe\n---\nBody"
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)
	if doc == nil {
		t.Fatal("expected non-nil doc")
	}
}

func TestParseClaudeMD(t *testing.T) {
	content := readFixture(t, "../../testdata/claude/basic.md")
	doc := ParseClaudeMD("CLAUDE.md", content)

	if doc.FileType != "claude_md" {
		t.Errorf("FileType = %q, want claude_md", doc.FileType)
	}

	body := doc.Parsed["body"].(string)
	if body != doc.Content {
		t.Error("body should equal content for CLAUDE.md")
	}

	bsl := doc.Parsed["body_start_line"].(int)
	if bsl != 1 {
		t.Errorf("body_start_line = %d, want 1", bsl)
	}

	// code_block_lines and content_code_block_lines should be identical
	cbl := doc.Parsed["code_block_lines"].(map[int]bool)
	ccbl := doc.Parsed["content_code_block_lines"].(map[int]bool)
	if len(cbl) != len(ccbl) {
		t.Error("code_block_lines and content_code_block_lines should be identical for CLAUDE.md")
	}
	if len(cbl) == 0 {
		t.Error("code_block_lines should not be empty (fixture has a code block)")
	}
}
