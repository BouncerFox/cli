package rules

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/bouncerfox/cli/pkg/document"
)

const maxLineLength = 10_000

var htmlCommentRe = regexp.MustCompile(`(?s)<!--(.*?)-->`)

func hasParseError(doc *document.ConfigDocument) bool {
	v, _ := doc.Parsed["_parse_error"].(bool)
	return v
}

func truncSnippet(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

func getParsedIntBoolMap(doc *document.ConfigDocument, key string) map[int]bool {
	if v, ok := doc.Parsed[key]; ok {
		if m, ok := v.(map[int]bool); ok {
			return m
		}
	}
	return nil
}

func getIntParam(ruleID, key string, defaultVal int) int {
	if p, ok := RuleParams[ruleID]; ok {
		switch v := p[key].(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return defaultVal
}

func getFloatParam(ruleID, key string, defaultVal float64) float64 {
	if p, ok := RuleParams[ruleID]; ok {
		switch v := p[key].(type) {
		case float64:
			return v
		case int:
			return float64(v)
		}
	}
	return defaultVal
}

// HookCommand represents an extracted hook name + command pair.
type HookCommand struct {
	Name    string
	Command string
}

// MCPServer represents an extracted MCP server name + config pair.
type MCPServer struct {
	Name   string
	Config map[string]any
}

// CheckLinePatterns scans lines against regex patterns, emitting one finding per matching line.
// The caller passes the appropriate codeBlockLines set and lineOffset for evidence line numbers.
func CheckLinePatterns(
	lines []string,
	patterns []*regexp.Regexp,
	doc *document.ConfigDocument,
	ruleID string,
	severity document.FindingSeverity,
	message, remediation string,
	codeBlockLines map[int]bool,
	lineOffset int,
) []document.ScanFinding {
	var findings []document.ScanFinding
	for i, line := range lines {
		lineNum := i + 1
		if codeBlockLines[lineNum] {
			continue
		}
		if len(line) > maxLineLength {
			line = line[:maxLineLength]
		}
		for _, pattern := range patterns {
			if pattern.MatchString(line) {
				snippet := strings.TrimSpace(line)
				if len(snippet) > 100 {
					snippet = snippet[:100]
				}
				findings = append(findings, document.ScanFinding{
					RuleID:   ruleID,
					Severity: severity,
					Message:  message,
					Evidence: map[string]any{
						"file":    doc.FilePath,
						"line":    lineNum + lineOffset,
						"snippet": snippet,
					},
					Remediation: remediation,
				})
				break // one finding per line
			}
		}
	}
	return findings
}

// GetFrontmatterLine returns the 1-based line number of a frontmatter field.
// Falls back to 1 if the field is not found.
func GetFrontmatterLine(doc *document.ConfigDocument, field string) int {
	fmLines, ok := doc.Parsed["frontmatter_lines"].(map[string]int)
	if !ok {
		return 1
	}
	if line, ok := fmLines[field]; ok {
		return line
	}
	return 1
}

func getBodyOffset(doc *document.ConfigDocument) int {
	if bsl, ok := doc.Parsed["body_start_line"].(int); ok {
		return bsl - 1
	}
	return 0
}

// FindHTMLComments finds non-trivial HTML comments in body text.
func FindHTMLComments(
	body string,
	doc *document.ConfigDocument,
	ruleID string,
	severity document.FindingSeverity,
	message, remediation string,
	minLength int,
) []document.ScanFinding {
	bodyOffset := getBodyOffset(doc)

	var findings []document.ScanFinding
	for _, match := range htmlCommentRe.FindAllStringSubmatchIndex(body, -1) {
		commentContent := strings.TrimSpace(body[match[2]:match[3]])
		if len(commentContent) > minLength {
			lineNum := strings.Count(body[:match[0]], "\n") + 1 + bodyOffset
			snippet := commentContent
			if len(snippet) > 100 {
				snippet = snippet[:100]
			}
			findings = append(findings, document.ScanFinding{
				RuleID:   ruleID,
				Severity: severity,
				Message:  message,
				Evidence: map[string]any{
					"file":            doc.FilePath,
					"line":            lineNum,
					"snippet":         snippet,
					"measured_length": len(commentContent),
				},
				Remediation: remediation,
			})
		}
	}
	return findings
}

// FindUnclosedHTMLComments detects <!-- without a matching -->.
func FindUnclosedHTMLComments(
	body string,
	doc *document.ConfigDocument,
	ruleID string,
	severity document.FindingSeverity,
) []document.ScanFinding {
	bodyOffset := getBodyOffset(doc)

	idx := 0
	for {
		start := strings.Index(body[idx:], "<!--")
		if start == -1 {
			break
		}
		start += idx
		end := strings.Index(body[start+4:], "-->")
		if end == -1 {
			lineNum := strings.Count(body[:start], "\n") + 1 + bodyOffset
			snippet := body[start:]
			if len(snippet) > 50 {
				snippet = snippet[:50]
			}
			return []document.ScanFinding{{
				RuleID:   ruleID,
				Severity: severity,
				Message:  "Unclosed HTML comment hides all subsequent content",
				Evidence: map[string]any{
					"file":    doc.FilePath,
					"line":    lineNum,
					"snippet": snippet,
				},
				Remediation: "Close the HTML comment with --> or remove it.",
			}}
		}
		idx = start + 4 + end + 3
	}
	return nil
}

// ExtractHookCommands walks settings hooks and returns all (hookName, command) pairs.
// Handles string, list, and nested matcher formats.
func ExtractHookCommands(settings map[string]any) []HookCommand {
	hooks, ok := settings["hooks"]
	if !ok {
		return nil
	}
	hooksMap, ok := hooks.(map[string]any)
	if !ok {
		return nil
	}

	var commands []HookCommand
	for hookName, hookConfig := range hooksMap {
		switch v := hookConfig.(type) {
		case string:
			if v != "" {
				commands = append(commands, HookCommand{hookName, v})
			}
		case map[string]any:
			if cmd, ok := v["command"].(string); ok && cmd != "" {
				commands = append(commands, HookCommand{hookName, cmd})
			}
		case []any:
			for _, item := range v {
				switch iv := item.(type) {
				case string:
					if iv != "" {
						commands = append(commands, HookCommand{hookName, iv})
					}
				case map[string]any:
					if cmd, ok := iv["command"].(string); ok && cmd != "" {
						commands = append(commands, HookCommand{hookName, cmd})
					}
					// Nested matcher format: {"matcher": "...", "hooks": [...]}
					if nested, ok := iv["hooks"].([]any); ok {
						for _, handler := range nested {
							if h, ok := handler.(map[string]any); ok {
								if cmd, ok := h["command"].(string); ok && cmd != "" {
									commands = append(commands, HookCommand{hookName, cmd})
								}
							}
						}
					}
				}
			}
		}
	}
	return commands
}

// URLMatchesAllowlist checks if a URL's domain matches any entry in the allowlist.
func URLMatchesAllowlist(rawURL string, allowlist []string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	domain := parsed.Hostname()
	if domain == "" {
		return false
	}

	for _, allowed := range allowlist {
		allowed = strings.TrimLeft(allowed, "*.")
		if domain == allowed || strings.HasSuffix(domain, "."+allowed) {
			return true
		}
	}
	return false
}

// IterMCPServers yields MCP server entries from parsed config.
func IterMCPServers(parsed map[string]any) []MCPServer {
	servers, ok := parsed["mcpServers"]
	if !ok {
		return nil
	}
	serversMap, ok := servers.(map[string]any)
	if !ok {
		return nil
	}

	var result []MCPServer
	for name, config := range serversMap {
		if configMap, ok := config.(map[string]any); ok {
			result = append(result, MCPServer{Name: name, Config: configMap})
		}
	}
	return result
}

// BuildMCPCommand builds the full command string from an MCP server config.
func BuildMCPCommand(serverConfig map[string]any) string {
	command, _ := serverConfig["command"].(string)
	args, ok := serverConfig["args"].([]any)
	if !ok || len(args) == 0 {
		return command
	}
	parts := []string{command}
	for _, a := range args {
		parts = append(parts, strings.TrimSpace(asString(a)))
	}
	return strings.Join(parts, " ")
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
