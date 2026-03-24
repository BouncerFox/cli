package rules

import (
	"regexp"
	"testing"

	"github.com/bouncerfox/cli/pkg/document"
)

func TestCheckLinePatterns(t *testing.T) {
	doc := &document.ConfigDocument{FilePath: "test.md"}

	t.Run("matches pattern on correct line", func(t *testing.T) {
		lines := []string{"safe line", "rm -rf /", "another safe"}
		patterns := []*regexp.Regexp{regexp.MustCompile(`rm\s+-rf`)}
		findings := CheckLinePatterns(lines, patterns, doc, "TEST_001",
			document.SeverityHigh, "destructive", "fix it", nil, 0)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		if findings[0].Evidence["line"] != 2 {
			t.Errorf("line = %v, want 2", findings[0].Evidence["line"])
		}
	})

	t.Run("skips code block lines", func(t *testing.T) {
		lines := []string{"safe", "rm -rf /", "safe"}
		cbl := map[int]bool{2: true}
		patterns := []*regexp.Regexp{regexp.MustCompile(`rm\s+-rf`)}
		findings := CheckLinePatterns(lines, patterns, doc, "TEST_001",
			document.SeverityHigh, "destructive", "fix it", cbl, 0)
		if len(findings) != 0 {
			t.Errorf("got %d findings, want 0 (code block line skipped)", len(findings))
		}
	})

	t.Run("does not skip code blocks when nil", func(t *testing.T) {
		lines := []string{"rm -rf /"}
		patterns := []*regexp.Regexp{regexp.MustCompile(`rm\s+-rf`)}
		findings := CheckLinePatterns(lines, patterns, doc, "TEST_001",
			document.SeverityHigh, "destructive", "fix it", nil, 0)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("one finding per line", func(t *testing.T) {
		lines := []string{"rm -rf / && rm -rf /tmp"}
		patterns := []*regexp.Regexp{
			regexp.MustCompile(`rm\s+-rf\s+/tmp`),
			regexp.MustCompile(`rm\s+-rf`),
		}
		findings := CheckLinePatterns(lines, patterns, doc, "TEST_001",
			document.SeverityHigh, "destructive", "fix it", nil, 0)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1 (one per line)", len(findings))
		}
	})

	t.Run("applies line offset", func(t *testing.T) {
		lines := []string{"rm -rf /"}
		patterns := []*regexp.Regexp{regexp.MustCompile(`rm\s+-rf`)}
		findings := CheckLinePatterns(lines, patterns, doc, "TEST_001",
			document.SeverityHigh, "destructive", "fix it", nil, 5)
		if findings[0].Evidence["line"] != 6 {
			t.Errorf("line = %v, want 6 (1 + offset 5)", findings[0].Evidence["line"])
		}
	})

	t.Run("truncates snippet to 100 chars", func(t *testing.T) {
		longLine := "rm -rf /" + string(make([]byte, 200))
		lines := []string{longLine}
		patterns := []*regexp.Regexp{regexp.MustCompile(`rm\s+-rf`)}
		findings := CheckLinePatterns(lines, patterns, doc, "TEST_001",
			document.SeverityHigh, "destructive", "fix it", nil, 0)
		snippet := findings[0].Evidence["snippet"].(string)
		if len(snippet) > 100 {
			t.Errorf("snippet length = %d, want <= 100", len(snippet))
		}
	})
}

func TestGetFrontmatterLine(t *testing.T) {
	doc := &document.ConfigDocument{
		Parsed: map[string]any{
			"frontmatter_lines": map[string]int{
				"name":        2,
				"description": 3,
			},
		},
	}

	if got := GetFrontmatterLine(doc, "name"); got != 2 {
		t.Errorf("GetFrontmatterLine(name) = %d, want 2", got)
	}
	if got := GetFrontmatterLine(doc, "missing"); got != 1 {
		t.Errorf("GetFrontmatterLine(missing) = %d, want 1", got)
	}
}

func TestFindHTMLComments(t *testing.T) {
	doc := &document.ConfigDocument{
		FilePath: "test.md",
		Parsed:   map[string]any{"body_start_line": 1},
	}

	t.Run("finds long comment", func(t *testing.T) {
		body := "text\n<!-- this is a hidden instruction for the agent -->\nmore"
		findings := FindHTMLComments(body, doc, "PS_004", document.SeverityWarn,
			"hidden instruction", "review it", 10)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("skips short comment", func(t *testing.T) {
		body := "<!-- ok -->"
		findings := FindHTMLComments(body, doc, "PS_004", document.SeverityWarn,
			"hidden", "fix", 10)
		if len(findings) != 0 {
			t.Errorf("got %d findings, want 0 (comment too short)", len(findings))
		}
	})
}

func TestFindUnclosedHTMLComments(t *testing.T) {
	doc := &document.ConfigDocument{
		FilePath: "test.md",
		Parsed:   map[string]any{"body_start_line": 1},
	}

	t.Run("finds unclosed comment", func(t *testing.T) {
		body := "text\n<!-- this is unclosed\nmore text"
		findings := FindUnclosedHTMLComments(body, doc, "PS_004", document.SeverityWarn)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("no finding when properly closed", func(t *testing.T) {
		body := "text\n<!-- closed -->\nmore text"
		findings := FindUnclosedHTMLComments(body, doc, "PS_004", document.SeverityWarn)
		if len(findings) != 0 {
			t.Errorf("got %d findings, want 0", len(findings))
		}
	})
}

func TestExtractHookCommands(t *testing.T) {
	t.Run("dict with command key", func(t *testing.T) {
		settings := map[string]any{
			"hooks": map[string]any{
				"PreToolUse": map[string]any{"command": "echo pre"},
			},
		}
		cmds := ExtractHookCommands(settings)
		if len(cmds) != 1 {
			t.Fatalf("got %d commands, want 1", len(cmds))
		}
		if cmds[0].Name != "PreToolUse" || cmds[0].Command != "echo pre" {
			t.Errorf("got %+v", cmds[0])
		}
	})

	t.Run("string command", func(t *testing.T) {
		settings := map[string]any{
			"hooks": map[string]any{
				"PreToolUse": "echo pre",
			},
		}
		cmds := ExtractHookCommands(settings)
		if len(cmds) != 1 {
			t.Fatalf("got %d commands, want 1", len(cmds))
		}
	})

	t.Run("list of commands", func(t *testing.T) {
		settings := map[string]any{
			"hooks": map[string]any{
				"PreToolUse": []any{"echo a", "echo b"},
			},
		}
		cmds := ExtractHookCommands(settings)
		if len(cmds) != 2 {
			t.Fatalf("got %d commands, want 2", len(cmds))
		}
	})

	t.Run("nested matcher format", func(t *testing.T) {
		settings := map[string]any{
			"hooks": map[string]any{
				"PreToolUse": []any{
					map[string]any{
						"matcher": "Bash",
						"hooks": []any{
							map[string]any{"command": "echo nested"},
						},
					},
				},
			},
		}
		cmds := ExtractHookCommands(settings)
		if len(cmds) != 1 {
			t.Fatalf("got %d commands, want 1", len(cmds))
		}
		if cmds[0].Command != "echo nested" {
			t.Errorf("command = %q, want 'echo nested'", cmds[0].Command)
		}
	})

	t.Run("no hooks", func(t *testing.T) {
		settings := map[string]any{}
		cmds := ExtractHookCommands(settings)
		if len(cmds) != 0 {
			t.Errorf("got %d commands, want 0", len(cmds))
		}
	})
}

func TestURLMatchesAllowlist(t *testing.T) {
	allowlist := []string{"github.com", "localhost", "*.example.com"}

	tests := []struct {
		url  string
		want bool
	}{
		{"https://github.com/foo", true},
		{"https://api.github.com/bar", true},
		{"http://localhost:3000", true},
		{"https://evil.com", false},
		{"https://example.com/foo", true},
		{"https://sub.example.com/foo", true},
		{"not a url", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := URLMatchesAllowlist(tt.url, allowlist)
			if got != tt.want {
				t.Errorf("URLMatchesAllowlist(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestIterMCPServers(t *testing.T) {
	parsed := map[string]any{
		"mcpServers": map[string]any{
			"server1": map[string]any{"command": "npx", "args": []any{"pkg"}},
			"server2": map[string]any{"command": "uvx"},
		},
	}
	servers := IterMCPServers(parsed)
	if len(servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(servers))
	}
}

func TestBuildMCPCommand(t *testing.T) {
	t.Run("command with args", func(t *testing.T) {
		config := map[string]any{
			"command": "npx",
			"args":    []any{"@my-org/server@1.0.0", "--port", "3000"},
		}
		got := BuildMCPCommand(config)
		want := "npx @my-org/server@1.0.0 --port 3000"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("command without args", func(t *testing.T) {
		config := map[string]any{"command": "my-server"}
		got := BuildMCPCommand(config)
		if got != "my-server" {
			t.Errorf("got %q, want 'my-server'", got)
		}
	})
}
