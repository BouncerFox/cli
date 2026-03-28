package rules

import (
	"strings"
	"testing"

	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/parser"
)

// ── QA_001 ──────────────────────────────────────────────────────────────────

func TestQA001_MissingBoth(t *testing.T) {
	doc := newSkillDoc("---\n---\nBody here.\n")
	findings := CheckQA001(doc, defaultRC())
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (name + description)", len(findings))
	}
	for _, f := range findings {
		if f.RuleID != "QA_001" {
			t.Errorf("ruleID = %q, want QA_001", f.RuleID)
		}
		if f.Severity != document.SeverityWarn {
			t.Errorf("severity = %q, want warn", f.Severity)
		}
	}
}

func TestQA001_MissingDescription(t *testing.T) {
	doc := newSkillDoc("---\nname: my-skill\n---\nBody here.\n")
	findings := CheckQA001(doc, defaultRC())
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Message, "description") {
		t.Errorf("message %q should mention 'description'", findings[0].Message)
	}
}

func TestQA001_MissingName(t *testing.T) {
	doc := newSkillDoc("---\ndescription: A good description here\n---\nBody here.\n")
	findings := CheckQA001(doc, defaultRC())
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Message, "name") {
		t.Errorf("message %q should mention 'name'", findings[0].Message)
	}
}

func TestQA001_AllPresent(t *testing.T) {
	doc := newSkillDoc("---\nname: my-skill\ndescription: A good description here\n---\nBody here.\n")
	findings := CheckQA001(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestQA001_NotSkillMD(t *testing.T) {
	doc := newClaudeMDDoc("# Claude context\nNo frontmatter needed.\n")
	findings := CheckQA001(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (non-skill_md)", len(findings))
	}
}

func TestQA001_EmptyDescription(t *testing.T) {
	doc := newSkillDoc("---\nname: my-skill\ndescription: \n---\nBody.\n")
	findings := CheckQA001(doc, defaultRC())
	// description is empty string — should flag it
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (empty description)", len(findings))
	}
}

// ── QA_002 ──────────────────────────────────────────────────────────────────

func TestQA002_Mismatch(t *testing.T) {
	doc := &document.ConfigDocument{
		FileType: document.FileTypeSkillMD,
		FilePath: "/repo/.claude/skills/my-skill/SKILL.md",
		Content:  "---\nname: wrong-name\ndescription: desc\n---\n",
		Parsed: map[string]any{
			"frontmatter": map[string]any{
				"name":        "wrong-name",
				"description": "desc",
			},
		},
	}
	findings := CheckQA002(doc, defaultRC())
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "QA_002" {
		t.Errorf("ruleID = %q, want QA_002", findings[0].RuleID)
	}
}

func TestQA002_Match(t *testing.T) {
	doc := &document.ConfigDocument{
		FileType: document.FileTypeSkillMD,
		FilePath: "/repo/.claude/skills/my-skill/SKILL.md",
		Content:  "---\nname: my-skill\ndescription: desc\n---\n",
		Parsed: map[string]any{
			"frontmatter": map[string]any{
				"name":        "my-skill",
				"description": "desc",
			},
		},
	}
	findings := CheckQA002(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestQA002_NoPathMatch(t *testing.T) {
	// File path does not match the skill path pattern
	doc := &document.ConfigDocument{
		FileType: document.FileTypeSkillMD,
		FilePath: "/repo/SKILL.md",
		Content:  "---\nname: anything\n---\n",
		Parsed: map[string]any{
			"frontmatter": map[string]any{"name": "anything"},
		},
	}
	findings := CheckQA002(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (no path match)", len(findings))
	}
}

func TestQA002_NoName(t *testing.T) {
	doc := &document.ConfigDocument{
		FileType: document.FileTypeSkillMD,
		FilePath: "/repo/.claude/skills/my-skill/SKILL.md",
		Content:  "---\ndescription: desc\n---\n",
		Parsed: map[string]any{
			"frontmatter": map[string]any{"description": "desc"},
		},
	}
	findings := CheckQA002(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (no name to compare)", len(findings))
	}
}

// ── QA_003 ──────────────────────────────────────────────────────────────────

func TestQA003_TooShort(t *testing.T) {
	doc := newSkillDoc("---\nname: s\ndescription: short\n---\n")
	findings := CheckQA003(doc, defaultRC())
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "QA_003" {
		t.Errorf("ruleID = %q, want QA_003", findings[0].RuleID)
	}
	if findings[0].Severity != document.SeverityWarn {
		t.Errorf("severity = %q, want warn", findings[0].Severity)
	}
	if findings[0].Evidence["measured_length"] == nil {
		t.Error("evidence missing measured_length")
	}
}

func TestQA003_LongEnough(t *testing.T) {
	doc := newSkillDoc("---\nname: s\ndescription: This is a sufficiently long description\n---\n")
	findings := CheckQA003(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestQA003_Empty(t *testing.T) {
	doc := newSkillDoc("---\nname: s\ndescription: \n---\n")
	findings := CheckQA003(doc, defaultRC())
	// empty description is handled by QA_001, QA_003 should not fire
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (empty description not flagged by QA_003)", len(findings))
	}
}

// ── QA_004 ──────────────────────────────────────────────────────────────────

func TestQA004_EmptyBody(t *testing.T) {
	doc := newSkillDoc("---\nname: s\n---\n")
	findings := CheckQA004(doc, defaultRC())
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "QA_004" {
		t.Errorf("ruleID = %q, want QA_004", findings[0].RuleID)
	}
}

func TestQA004_WhitespaceBody(t *testing.T) {
	doc := newSkillDoc("---\nname: s\n---\n   \n\t\n")
	findings := CheckQA004(doc, defaultRC())
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (whitespace-only body)", len(findings))
	}
}

func TestQA004_WithBody(t *testing.T) {
	doc := newSkillDoc("---\nname: s\n---\nSome content here.\n")
	findings := CheckQA004(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

// ── QA_005 ──────────────────────────────────────────────────────────────────

func TestQA005_OnlyCodeBlock(t *testing.T) {
	body := "```python\nprint('hello world')\n```\n"
	doc := newSkillDoc("---\nname: s\n---\n" + body)
	findings := CheckQA005(doc, defaultRC())
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (body is only code, no prose)", len(findings))
	}
	if findings[0].RuleID != "QA_005" {
		t.Errorf("ruleID = %q, want QA_005", findings[0].RuleID)
	}
	if findings[0].Severity != document.SeverityInfo {
		t.Errorf("severity = %q, want info", findings[0].Severity)
	}
}

func TestQA005_GoodProse(t *testing.T) {
	body := "This skill does something useful and has enough prose content to pass the check.\n"
	doc := newSkillDoc("---\nname: s\n---\n" + body)
	findings := CheckQA005(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestQA005_EmptyBodyNotFired(t *testing.T) {
	// QA_005 should not fire when body is completely empty (QA_004 handles that)
	doc := newSkillDoc("---\nname: s\n---\n")
	findings := CheckQA005(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (QA_004 handles empty body)", len(findings))
	}
}

// ── QA_006 ──────────────────────────────────────────────────────────────────

func TestQA006_MissingTools(t *testing.T) {
	doc := newSkillDoc("---\nname: s\ndescription: desc\n---\nBody.\n")
	findings := CheckQA006(doc, defaultRC())
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "QA_006" {
		t.Errorf("ruleID = %q, want QA_006", findings[0].RuleID)
	}
	if findings[0].Severity != document.SeverityInfo {
		t.Errorf("severity = %q, want info", findings[0].Severity)
	}
}

func TestQA006_HasTools(t *testing.T) {
	doc := newSkillDoc("---\nname: s\ndescription: desc\ntools:\n  - Read\n---\nBody.\n")
	findings := CheckQA006(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestQA006_NotSkillMD(t *testing.T) {
	doc := newClaudeMDDoc("# Hello\n")
	findings := CheckQA006(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

// ── QA_007 ──────────────────────────────────────────────────────────────────

func TestQA007_ValidName(t *testing.T) {
	doc := newSkillDoc("---\nname: my-skill-123\ndescription: desc\n---\n")
	findings := CheckQA007(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestQA007_UpperCase(t *testing.T) {
	doc := newSkillDoc("---\nname: MySkill\ndescription: desc\n---\n")
	findings := CheckQA007(doc, defaultRC())
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "QA_007" {
		t.Errorf("ruleID = %q, want QA_007", findings[0].RuleID)
	}
}

func TestQA007_StartsWithHyphen(t *testing.T) {
	doc := newSkillDoc("---\nname: -bad-name\ndescription: desc\n---\n")
	findings := CheckQA007(doc, defaultRC())
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestQA007_WithSpaces(t *testing.T) {
	doc := newSkillDoc("---\nname: bad name\ndescription: desc\n---\n")
	findings := CheckQA007(doc, defaultRC())
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestQA007_NoName(t *testing.T) {
	doc := newSkillDoc("---\ndescription: desc\n---\n")
	findings := CheckQA007(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (no name = no finding from QA_007)", len(findings))
	}
}

// ── QA_008 ──────────────────────────────────────────────────────────────────

func TestQA008_TooLarge(t *testing.T) {
	// Create content > 50KB
	content := strings.Repeat("a", 51*1024)
	doc := &document.ConfigDocument{
		FileType: document.FileTypeClaudeMD,
		FilePath: "CLAUDE.md",
		Content:  content,
		Parsed:   map[string]any{},
	}
	findings := CheckQA008(doc, defaultRC())
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "QA_008" {
		t.Errorf("ruleID = %q, want QA_008", findings[0].RuleID)
	}
	if findings[0].Severity != document.SeverityWarn {
		t.Errorf("severity = %q, want warn", findings[0].Severity)
	}
}

func TestQA008_SmallEnough(t *testing.T) {
	content := strings.Repeat("a", 1024)
	doc := &document.ConfigDocument{
		FileType: document.FileTypeClaudeMD,
		FilePath: "CLAUDE.md",
		Content:  content,
		Parsed:   map[string]any{},
	}
	findings := CheckQA008(doc, defaultRC())
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestQA008_AppliesToAllFileTypes(t *testing.T) {
	// QA_008 applies to all file types, not just skill_md
	content := strings.Repeat("x", 52*1024)
	for _, ft := range []string{
		document.FileTypeSkillMD,
		document.FileTypeClaudeMD,
		document.FileTypeAgentMD,
		document.FileTypeSettingsJSON,
		document.FileTypeMCPJSON,
	} {
		doc := &document.ConfigDocument{
			FileType: ft,
			FilePath: "test",
			Content:  content,
			Parsed:   map[string]any{},
		}
		findings := CheckQA008(doc, defaultRC())
		if len(findings) != 1 {
			t.Errorf("file_type=%s: got %d findings, want 1", ft, len(findings))
		}
	}
}

func newAgentDoc(content string) *document.ConfigDocument {
	return parser.ParseFrontmatterMD(document.FileTypeAgentMD, "agent.md", content)
}

// ── QA boundary tests ────────────────────────────────────────────────────────

func TestQA003_ExactlyMinLength(t *testing.T) {
	// Default min is 20 chars — exactly 20 should pass
	content := "---\nname: test\ndescription: exactly twenty chars\n---\nBody content here."
	doc := newSkillDoc(content)
	findings := CheckQA003(doc, defaultRC())
	if len(findings) > 0 {
		t.Error("description with exactly min_description_length should not trigger")
	}
}
