package rules

import (
	"testing"

	"github.com/bouncerfox/cli/pkg/document"
)

func TestCheckSEC021_DangerousTraversal(t *testing.T) {
	doc := &document.ConfigDocument{
		FileType: document.FileTypeClaudeMD,
		FilePath: "CLAUDE.md",
		Content:  "@../../.env\nSome instructions.",
		Parsed:   map[string]any{},
	}
	findings := CheckSEC021(doc, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != document.SeverityHigh {
		t.Errorf("severity = %s, want high", findings[0].Severity)
	}
}

func TestCheckSEC021_AbsolutePath(t *testing.T) {
	doc := &document.ConfigDocument{
		FileType: document.FileTypeClaudeMD,
		FilePath: "CLAUDE.md",
		Content:  "@/etc/passwd",
		Parsed:   map[string]any{},
	}
	findings := CheckSEC021(doc, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestCheckSEC021_HomePath(t *testing.T) {
	doc := &document.ConfigDocument{
		FileType: document.FileTypeClaudeMD,
		FilePath: "CLAUDE.md",
		Content:  "@~/.claude/.credentials.json",
		Parsed:   map[string]any{},
	}
	findings := CheckSEC021(doc, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestCheckSEC021_SensitivePath(t *testing.T) {
	doc := &document.ConfigDocument{
		FileType: document.FileTypeClaudeMD,
		FilePath: "CLAUDE.md",
		Content:  "@config/.env.production",
		Parsed:   map[string]any{},
	}
	findings := CheckSEC021(doc, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestCheckSEC021_BenignImport_NoFinding(t *testing.T) {
	doc := &document.ConfigDocument{
		FileType: document.FileTypeClaudeMD,
		FilePath: "CLAUDE.md",
		Content:  "@docs/coding-standards.md\n@src/guidelines.md",
		Parsed:   map[string]any{},
	}
	findings := CheckSEC021(doc, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for benign imports, got %d", len(findings))
	}
}

func TestCheckSEC021_EmailNotMatched(t *testing.T) {
	doc := &document.ConfigDocument{
		FileType: document.FileTypeClaudeMD,
		FilePath: "CLAUDE.md",
		Content:  "Contact user@example.com for help.",
		Parsed:   map[string]any{},
	}
	findings := CheckSEC021(doc, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for email, got %d", len(findings))
	}
}

func TestCheckSEC021_MidLineMention_NoFinding(t *testing.T) {
	doc := &document.ConfigDocument{
		FileType: document.FileTypeClaudeMD,
		FilePath: "CLAUDE.md",
		Content:  "Please see @alice for code review.",
		Parsed:   map[string]any{},
	}
	findings := CheckSEC021(doc, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for mid-line mention, got %d", len(findings))
	}
}

func TestCheckSEC021_MultipleDangerous(t *testing.T) {
	doc := &document.ConfigDocument{
		FileType: document.FileTypeCursorRules,
		FilePath: ".cursorrules",
		Content:  "@../secrets.yml\n@~/tokens.json",
		Parsed:   map[string]any{},
	}
	findings := CheckSEC021(doc, nil)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
}
