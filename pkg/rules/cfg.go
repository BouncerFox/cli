package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/parser"
)

var bashWildcardRe = regexp.MustCompile(`(?i)bash\(\s*\*\s*\)`)
var writeWildcardRe = regexp.MustCompile(`(?i)^Write\(\s*\*\s*\)$`)
var mcpWildcardRe = regexp.MustCompile(`(?i)^mcp__[^*]*\*`)

var hookInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\$\(`),
	regexp.MustCompile("`"),
	regexp.MustCompile(`;\s`),
	regexp.MustCompile(`\|\s`),
	regexp.MustCompile(`&&\s`),
}

var permissiveFlagRe = regexp.MustCompile(
	`(?i)--(allow-all|no-sandbox|disable-security|trust-all|unsafe|no-verify|skip-validation|privileged)\b|\s-A(?:\s|$)`,
)

var permissiveFlagPatterns = []*regexp.Regexp{permissiveFlagRe}

// CheckCFG001 checks for unrestricted bash tool in allowedTools.
func CheckCFG001(doc *document.ConfigDocument, rc *document.RuleContext) []document.ScanFinding {
	if doc.FileType != document.FileTypeSettingsJSON || hasParseError(doc) {
		return nil
	}

	allowedTools, _ := doc.Parsed["allowedTools"].([]any)
	for _, t := range allowedTools {
		s, ok := t.(string)
		if !ok {
			continue
		}
		toolTrimmed := strings.TrimSpace(s)
		if strings.EqualFold(toolTrimmed, "bash") || bashWildcardRe.MatchString(toolTrimmed) {
			return []document.ScanFinding{{
				RuleID:   "CFG_001",
				Severity: document.SeverityHigh,
				Message:  "allowedTools grants 'Bash' with no restrictions",
				Evidence: map[string]any{
					"file":    doc.FilePath,
					"line":    parser.FindJSONKeyLine(doc.Content, "allowedTools"),
					"snippet": toolTrimmed,
				},
				Remediation: "Restrict bash tool with explicit command patterns.",
			}}
		}
	}

	return nil
}

// CheckCFG002 checks for Write tool in allowedTools.
func CheckCFG002(doc *document.ConfigDocument, rc *document.RuleContext) []document.ScanFinding {
	if doc.FileType != document.FileTypeSettingsJSON || hasParseError(doc) {
		return nil
	}

	allowedTools, _ := doc.Parsed["allowedTools"].([]any)
	for _, t := range allowedTools {
		s, ok := t.(string)
		if !ok {
			continue
		}
		toolTrimmed := strings.TrimSpace(s)
		if strings.EqualFold(toolTrimmed, "write") || writeWildcardRe.MatchString(toolTrimmed) {
			return []document.ScanFinding{{
				RuleID:   "CFG_002",
				Severity: document.SeverityWarn,
				Message:  "allowedTools contains 'Write' tool — grants unrestricted file write access",
				Evidence: map[string]any{
					"file":    doc.FilePath,
					"line":    parser.FindJSONKeyLine(doc.Content, "allowedTools"),
					"snippet": toolTrimmed,
				},
				Remediation: "Restrict Write tool to specific file paths.",
			}}
		}
	}

	return nil
}

// CheckCFG003 checks for mcp__* wildcard patterns in allowedTools.
func CheckCFG003(doc *document.ConfigDocument, rc *document.RuleContext) []document.ScanFinding {
	if doc.FileType != document.FileTypeSettingsJSON || hasParseError(doc) {
		return nil
	}

	allowedTools, _ := doc.Parsed["allowedTools"].([]any)
	for _, t := range allowedTools {
		s, ok := t.(string)
		if !ok {
			continue
		}
		toolTrimmed := strings.TrimSpace(s)
		if mcpWildcardRe.MatchString(toolTrimmed) {
			return []document.ScanFinding{{
				RuleID:   "CFG_003",
				Severity: document.SeverityHigh,
				Message:  "allowedTools contains MCP wildcard pattern — grants broad MCP tool access",
				Evidence: map[string]any{
					"file":    doc.FilePath,
					"line":    parser.FindJSONKeyLine(doc.Content, "allowedTools"),
					"snippet": toolTrimmed,
				},
				Remediation: "Specify exact MCP tool names instead of wildcards.",
			}}
		}
	}

	return nil
}

// CheckCFG004 checks hook commands for shell injection patterns.
func CheckCFG004(doc *document.ConfigDocument, rc *document.RuleContext) []document.ScanFinding {
	if hasParseError(doc) {
		return nil
	}
	switch doc.FileType {
	case document.FileTypeSettingsJSON, document.FileTypeHooksJSON:
		return checkCommandPatterns(doc, ExtractHookCommands(doc.Parsed), hookInjectionPatterns,
			"CFG_004", document.SeverityHigh,
			"Hook '%s' contains shell injection risk pattern",
			"Avoid shell metacharacters in hook commands; use explicit argument lists.")
	case document.FileTypeLSPJSON:
		return checkCommandPatterns(doc, ExtractLSPCommands(doc), hookInjectionPatterns,
			"CFG_004", document.SeverityHigh,
			"LSP server '%s' contains shell injection risk pattern",
			"Avoid shell metacharacters in LSP server commands; use explicit argument lists.")
	}
	return nil
}

// CheckCFG005 checks if there are too many allowed tools (> 20).
func CheckCFG005(doc *document.ConfigDocument, rc *document.RuleContext) []document.ScanFinding {
	if doc.FileType != document.FileTypeSettingsJSON || hasParseError(doc) {
		return nil
	}

	allowedTools, _ := doc.Parsed["allowedTools"].([]any)
	if len(allowedTools) <= 20 {
		return nil
	}

	return []document.ScanFinding{{
		RuleID:   "CFG_005",
		Severity: document.SeverityInfo,
		Message:  fmt.Sprintf("allowedTools contains %d tools — consider reducing permissions", len(allowedTools)),
		Evidence: map[string]any{
			"file":    doc.FilePath,
			"line":    parser.FindJSONKeyLine(doc.Content, "allowedTools"),
			"snippet": "",
		},
		Remediation: "Reduce the number of allowed tools to the minimum required.",
	}}
}

// CheckCFG006 checks if deniedTools is missing or empty.
func CheckCFG006(doc *document.ConfigDocument, rc *document.RuleContext) []document.ScanFinding {
	if doc.FileType != document.FileTypeSettingsJSON || hasParseError(doc) {
		return nil
	}

	deniedTools, exists := doc.Parsed["deniedTools"]
	if !exists {
		return []document.ScanFinding{{
			RuleID:   "CFG_006",
			Severity: document.SeverityInfo,
			Message:  "No 'deniedTools' key found — consider explicitly denying dangerous tools",
			Evidence: map[string]any{
				"file":    doc.FilePath,
				"line":    1,
				"snippet": "",
			},
			Remediation: "Add a 'deniedTools' list to explicitly block dangerous tools.",
		}}
	}

	if list, ok := deniedTools.([]any); ok && len(list) == 0 {
		return []document.ScanFinding{{
			RuleID:   "CFG_006",
			Severity: document.SeverityInfo,
			Message:  "'deniedTools' is empty — consider explicitly denying dangerous tools",
			Evidence: map[string]any{
				"file":    doc.FilePath,
				"line":    parser.FindJSONKeyLine(doc.Content, "deniedTools"),
				"snippet": "",
			},
			Remediation: "Add tools to the 'deniedTools' list to explicitly block dangerous tools.",
		}}
	}

	return nil
}

// CheckCFG009 checks for permissive flags in MCP server args and hook commands.
func CheckCFG009(doc *document.ConfigDocument, rc *document.RuleContext) []document.ScanFinding {
	if hasParseError(doc) {
		return nil
	}

	switch doc.FileType {
	case document.FileTypeSettingsJSON, document.FileTypeHooksJSON:
		return checkCommandPatterns(doc, ExtractHookCommands(doc.Parsed), permissiveFlagPatterns,
			"CFG_009", document.SeverityHigh,
			"Hook '%s' uses a permissive/unsafe flag",
			"Remove broad permission flags and grant specific permissions only.")
	case document.FileTypeMCPJSON:
		var findings []document.ScanFinding
		for _, srv := range IterMCPServers(doc.Parsed) {
			fullCmd := BuildMCPCommand(srv.Config)
			if permissiveFlagRe.MatchString(fullCmd) {
				findings = append(findings, document.ScanFinding{
					RuleID:   "CFG_009",
					Severity: document.SeverityHigh,
					Message:  fmt.Sprintf("MCP server '%s' uses a permissive/unsafe flag", srv.Name),
					Evidence: map[string]any{
						"file":    doc.FilePath,
						"line":    parser.FindJSONKeyLine(doc.Content, srv.Name),
						"snippet": truncSnippet(fullCmd, 100),
					},
					Remediation: "Remove broad permission flags and grant specific permissions only.",
				})
			}
		}
		return findings
	case document.FileTypeLSPJSON:
		return checkCommandPatterns(doc, ExtractLSPCommands(doc), permissiveFlagPatterns,
			"CFG_009", document.SeverityHigh,
			"LSP server '%s' uses a permissive/unsafe flag",
			"Remove broad permission flags and grant specific permissions only.")
	}

	return nil
}
