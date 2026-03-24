package parser

import (
	"os"
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
