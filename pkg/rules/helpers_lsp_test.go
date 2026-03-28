package rules

import (
	"testing"

	"github.com/bouncerfox/cli/pkg/document"
)

func TestExtractLSPCommands(t *testing.T) {
	tests := []struct {
		name   string
		parsed map[string]any
		want   int
	}{
		{
			"single server",
			map[string]any{
				"go": map[string]any{
					"command": "gopls",
					"args":    []any{"serve"},
				},
			},
			1,
		},
		{
			"multiple servers",
			map[string]any{
				"go": map[string]any{
					"command": "gopls",
					"args":    []any{"serve"},
				},
				"python": map[string]any{
					"command": "pylsp",
				},
			},
			2,
		},
		{
			"no command field",
			map[string]any{
				"go": map[string]any{
					"extensionToLanguage": map[string]any{".go": "go"},
				},
			},
			0,
		},
		{
			"non-object value",
			map[string]any{
				"version": "1.0",
			},
			0,
		},
		{
			"empty",
			map[string]any{},
			0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &document.ConfigDocument{
				FileType: document.FileTypeLSPJSON,
				Parsed:   tt.parsed,
			}
			got := ExtractLSPCommands(doc)
			if len(got) != tt.want {
				t.Errorf("ExtractLSPCommands() returned %d commands, want %d", len(got), tt.want)
			}
		})
	}
}

func TestExtractLSPCommands_CommandContent(t *testing.T) {
	doc := &document.ConfigDocument{
		FileType: document.FileTypeLSPJSON,
		Parsed: map[string]any{
			"go": map[string]any{
				"command": "gopls",
				"args":    []any{"serve", "-rpc.trace"},
			},
		},
	}
	cmds := ExtractLSPCommands(doc)
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if cmds[0].Command != "gopls serve -rpc.trace" {
		t.Errorf("command = %q, want %q", cmds[0].Command, "gopls serve -rpc.trace")
	}
	if cmds[0].Name != "go" {
		t.Errorf("name = %q, want %q", cmds[0].Name, "go")
	}
}
