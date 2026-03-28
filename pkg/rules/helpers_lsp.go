package rules

import "github.com/bouncerfox/cli/pkg/document"

// ExtractLSPCommands extracts command strings from .lsp.json documents.
// Each top-level key is a language server name; entries without a "command" field are skipped.
func ExtractLSPCommands(doc *document.ConfigDocument) []HookCommand {
	var commands []HookCommand
	for name, v := range doc.Parsed {
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := entry["command"].(string); !ok {
			continue
		}
		if cmd := BuildMCPCommand(entry); cmd != "" {
			commands = append(commands, HookCommand{Name: name, Command: cmd})
		}
	}
	return commands
}
