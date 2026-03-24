package document

type FindingSeverity string

const (
	SeverityInfo     FindingSeverity = "info"
	SeverityWarn     FindingSeverity = "warn"
	SeverityHigh     FindingSeverity = "high"
	SeverityCritical FindingSeverity = "critical"
)

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
	FileTypeSkillMD      = "skill_md"
	FileTypeClaudeMD     = "claude_md"
	FileTypeAgentMD      = "agent_md"
	FileTypeSettingsJSON = "settings_json"
	FileTypeMCPJSON      = "mcp_json"
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

type RuleMetadata struct {
	ID               string
	Name             string
	Category         string
	Description      string
	Remediation      string
	DefaultSeverity  FindingSeverity
	DefaultFileTypes []string
	Check            func(*ConfigDocument) []ScanFinding
}
