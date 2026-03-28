package parser

import (
	"strings"
	"testing"
)

func TestIsGovernedFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{".claude/skills/my-skill/SKILL.md", true},
		{"CLAUDE.md", true},
		{"sub/CLAUDE.md", true},
		{"CLAUDE.local.md", true},
		{".claude/settings.json", true},
		{".claude/settings.local.json", true},
		{".mcp.json", true},
		{"sub/.mcp.json", true},
		{".claude/agents/helper.md", true},
		{".claude/commands/deploy.md", true},
		{"random-file.txt", false},
		{"src/main.go", false},
		{"../../../etc/passwd", false},
		// Claude extended
		{".claude/rules/security.md", true},
		{".claude/rules/sub/testing.md", true},
		{"sub/.claude/rules/sec.md", true},
		{".claude-plugin/plugin.json", true},
		{"hooks/hooks.json", true},
		{"sub/hooks/hooks.json", true},
		{".lsp.json", true},
		{"sub/.lsp.json", true},
		// Other tools
		{".cursorrules", true},
		{"sub/.cursorrules", true},
		{".windsurfrules", true},
		{"AGENTS.md", true},
		{"sub/AGENTS.md", true},
		{".github/copilot-instructions.md", true},
		// Negative cases
		{".claude/rules/.md", false},
		{"hooks.json", false},
		{"plugin.json", false},
		{"lsp.json", false},
		{"agents.md", false},
		{"cursorrules", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := IsGovernedFile(tt.path)
			if got != tt.want {
				t.Errorf("IsGovernedFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsGovernedFile_URLEncodedTraversal(t *testing.T) {
	// URL-encoded %2e%2e is not actual ".." on the filesystem — the CLI operates
	// on OS paths, not URLs. The regex may still match CLAUDE.md in the path,
	// which is correct: the path traversal check only blocks literal ".." segments.
	// This test documents the behavior.
	_ = IsGovernedFile("%2e%2e/%2e%2e/CLAUDE.md")
}

func TestIsGovernedFile_NullByteInPath(t *testing.T) {
	if IsGovernedFile("CLAUDE.md\x00.txt") {
		t.Error("null byte in path should not match")
	}
}

func TestIsGovernedFile_CaseSensitivity(t *testing.T) {
	if IsGovernedFile("claude.md") {
		t.Error("lowercase claude.md should not be governed")
	}
}

func TestRouteAndParse_EmptyContent(t *testing.T) {
	doc := RouteAndParse("CLAUDE.md", "")
	if doc == nil {
		t.Fatal("expected non-nil doc for empty content")
	}
}

func TestRouteAndParse_PathTraversalInContent(t *testing.T) {
	doc := RouteAndParse("../../../CLAUDE.md", "content")
	if doc != nil {
		t.Error("path traversal should be rejected (nil doc)")
	}
}

func TestValidateFilePath_VeryLongPath(t *testing.T) {
	path := strings.Repeat("a/", 1000) + "CLAUDE.md"
	// Should not panic
	_ = validateFilePath(path)
}

func TestRouteAndParse(t *testing.T) {
	tests := []struct {
		path     string
		content  string
		wantType string
		wantNil  bool
	}{
		{
			".claude/skills/my-skill/SKILL.md",
			"---\nname: test\n---\nbody",
			"skill_md",
			false,
		},
		{
			"CLAUDE.md",
			"# Instructions",
			"claude_md",
			false,
		},
		{
			"sub/CLAUDE.md",
			"# Instructions",
			"claude_md",
			false,
		},
		{
			"CLAUDE.local.md",
			"# Local",
			"claude_md",
			false,
		},
		{
			".claude/settings.json",
			`{"allowedTools": []}`,
			"settings_json",
			false,
		},
		{
			".mcp.json",
			`{"mcpServers": {}}`,
			"mcp_json",
			false,
		},
		{
			".claude/agents/helper.md",
			"---\nname: helper\n---\nbody",
			"agent_md",
			false,
		},
		{
			".claude/commands/deploy.md",
			"---\nname: deploy\n---\nbody",
			"skill_md",
			false,
		},
		{
			"random.txt",
			"not governed",
			"",
			true,
		},
		{
			"../../../etc/passwd",
			"root:x:0",
			"",
			true,
		},
		{
			".claude/rules/security.md",
			"---\npaths:\n  - src/**\n---\nDo not commit secrets.",
			"rules_md",
			false,
		},
		{
			".claude-plugin/plugin.json",
			`{"name": "test", "version": "1.0.0"}`,
			"plugin_json",
			false,
		},
		{
			"hooks/hooks.json",
			`{"hooks": {"PreToolUse": [{"command": "echo hi"}]}}`,
			"hooks_json",
			false,
		},
		{
			".lsp.json",
			`{"go": {"command": "gopls", "args": ["serve"]}}`,
			"lsp_json",
			false,
		},
		{
			".cursorrules",
			"Use TypeScript for all new files.",
			"cursor_rules",
			false,
		},
		{
			".windsurfrules",
			"Follow ESLint config.",
			"windsurf_rules",
			false,
		},
		{
			"AGENTS.md",
			"# Agent Config",
			"agents_md",
			false,
		},
		{
			".github/copilot-instructions.md",
			"# Copilot Instructions",
			"copilot_md",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			doc := RouteAndParse(tt.path, tt.content)
			if tt.wantNil {
				if doc != nil {
					t.Errorf("expected nil, got doc with type %q", doc.FileType)
				}
				return
			}
			if doc == nil {
				t.Fatal("expected non-nil doc")
			}
			if doc.FileType != tt.wantType {
				t.Errorf("FileType = %q, want %q", doc.FileType, tt.wantType)
			}
		})
	}
}
