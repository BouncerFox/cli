package document

import "context"

type FindingSeverity string

const (
	SeverityInfo     FindingSeverity = "info"
	SeverityWarn     FindingSeverity = "warn"
	SeverityHigh     FindingSeverity = "high"
	SeverityCritical FindingSeverity = "critical"
)

func (s FindingSeverity) String() string {
	return string(s)
}

func (s FindingSeverity) Level() int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityWarn:
		return 1
	case SeverityHigh:
		return 2
	case SeverityCritical:
		return 3
	default:
		return -1
	}
}

const (
	FileTypeSkillMD       = "skill_md"
	FileTypeClaudeMD      = "claude_md"
	FileTypeAgentMD       = "agent_md"
	FileTypeSettingsJSON  = "settings_json"
	FileTypeMCPJSON       = "mcp_json"
	FileTypeRulesMD       = "rules_md"
	FileTypePluginJSON    = "plugin_json"
	FileTypeHooksJSON     = "hooks_json"
	FileTypeLSPJSON       = "lsp_json"
	FileTypeCursorRules   = "cursor_rules"
	FileTypeWindsurfRules = "windsurf_rules"
	FileTypeCopilotMD     = "copilot_md"
	FileTypeAgentsMD      = "agents_md"
)

type ConfigDocument struct {
	FileType    string
	FilePath    string
	Content     string
	Parsed      map[string]any
	ContentHash string
}

type ScanFinding struct {
	RuleID      string
	Severity    FindingSeverity
	Message     string
	Evidence    map[string]any
	Remediation string
}

// RuleContext carries per-scan state to check functions.
type RuleContext struct {
	Ctx    context.Context
	Params map[string]map[string]any // rule ID → param name → value
}

type RuleMetadata struct {
	ID               string
	Name             string
	Category         string
	Description      string
	Remediation      string
	DefaultSeverity  FindingSeverity
	DefaultFileTypes []string
	Check            func(*ConfigDocument, *RuleContext) []ScanFinding
}
