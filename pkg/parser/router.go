package parser

import (
	"regexp"
	"strings"

	"github.com/bouncerfox/cli/pkg/document"
)

type parserFunc func(filePath, content string) *document.ConfigDocument

type route struct {
	pattern  *regexp.Regexp
	fileType string
	parser   parserFunc
}

func fmParser(fileType string) parserFunc {
	return func(filePath, content string) *document.ConfigDocument {
		return ParseFrontmatterMD(fileType, filePath, content)
	}
}

func jsonParser(fileType string) parserFunc {
	return func(filePath, content string) *document.ConfigDocument {
		return ParseJSONConfig(fileType, filePath, content)
	}
}

func mdParser(fileType string) parserFunc {
	return func(filePath, content string) *document.ConfigDocument {
		doc := ParseClaudeMD(filePath, content)
		doc.FileType = fileType
		return doc
	}
}

var routeTable = []route{
	// Claude core
	{regexp.MustCompile(`\.claude/skills/.+/SKILL\.md$`), document.FileTypeSkillMD, fmParser(document.FileTypeSkillMD)},
	{regexp.MustCompile(`(^|/)CLAUDE\.md$`), document.FileTypeClaudeMD, ParseClaudeMD},
	{regexp.MustCompile(`(^|/)CLAUDE\.local\.md$`), document.FileTypeClaudeMD, ParseClaudeMD},
	{regexp.MustCompile(`\.claude/settings[^/]*\.json$`), document.FileTypeSettingsJSON, jsonParser(document.FileTypeSettingsJSON)},
	{regexp.MustCompile(`(^|/)\.mcp\.json$`), document.FileTypeMCPJSON, jsonParser(document.FileTypeMCPJSON)},
	{regexp.MustCompile(`\.claude/agents/[^/]+\.md$`), document.FileTypeAgentMD, fmParser(document.FileTypeAgentMD)},
	{regexp.MustCompile(`\.claude/commands/[^/]+\.md$`), document.FileTypeSkillMD, fmParser(document.FileTypeSkillMD)},
	// Claude extended — rules use fmParser because they support paths: frontmatter
	{regexp.MustCompile(`\.claude/rules/.+\.md$`), document.FileTypeRulesMD, fmParser(document.FileTypeRulesMD)},
	{regexp.MustCompile(`\.claude-plugin/plugin\.json$`), document.FileTypePluginJSON, jsonParser(document.FileTypePluginJSON)},
	{regexp.MustCompile(`(^|/)hooks/hooks\.json$`), document.FileTypeHooksJSON, jsonParser(document.FileTypeHooksJSON)},
	{regexp.MustCompile(`(^|/)\.lsp\.json$`), document.FileTypeLSPJSON, jsonParser(document.FileTypeLSPJSON)},
	// Other AI tools
	{regexp.MustCompile(`(^|/)\.cursorrules$`), document.FileTypeCursorRules, mdParser(document.FileTypeCursorRules)},
	{regexp.MustCompile(`(^|/)\.windsurfrules$`), document.FileTypeWindsurfRules, mdParser(document.FileTypeWindsurfRules)},
	{regexp.MustCompile(`\.github/copilot-instructions\.md$`), document.FileTypeCopilotMD, mdParser(document.FileTypeCopilotMD)},
	{regexp.MustCompile(`(^|/)AGENTS\.md$`), document.FileTypeAgentsMD, mdParser(document.FileTypeAgentsMD)},
	// Filename-only fallbacks for unique names not caught by path-specific routes above
	{regexp.MustCompile(`(^|/)SKILL\.md$`), document.FileTypeSkillMD, fmParser(document.FileTypeSkillMD)},
}

func validateFilePath(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == ".." {
			return false
		}
	}
	return true
}

// IsGovernedFile checks if a file path matches any governed config pattern.
func IsGovernedFile(path string) bool {
	if !validateFilePath(path) {
		return false
	}
	for _, r := range routeTable {
		if r.pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// RouteAndParse routes a file path to the correct parser and returns a ConfigDocument.
// Returns nil if no pattern matches or path contains traversal.
func RouteAndParse(filePath, content string) *document.ConfigDocument {
	if !validateFilePath(filePath) {
		return nil
	}
	for _, r := range routeTable {
		if r.pattern.MatchString(filePath) {
			return r.parser(filePath, content)
		}
	}
	return nil
}
