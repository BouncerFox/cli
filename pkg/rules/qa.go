package rules

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/parser"
)

var skillNameFromPathRe = regexp.MustCompile(`\.claude/skills/([^/]+)/SKILL\.md$`)
var validSkillNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// CheckQA001 checks that required frontmatter fields (name, description) exist.
func CheckQA001(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeSkillMD {
		return nil
	}

	fm, _ := doc.Parsed["frontmatter"].(map[string]any)
	var findings []document.ScanFinding

	for _, field := range []string{"name", "description"} {
		val, exists := fm[field]
		missing := !exists
		if !missing {
			if s, ok := val.(string); ok && strings.TrimSpace(s) == "" {
				missing = true
			} else if val == nil {
				missing = true
			}
		}
		if missing {
			findings = append(findings, document.ScanFinding{
				RuleID:   "QA_001",
				Severity: document.SeverityWarn,
				Message:  "Missing '" + field + "' in frontmatter",
				Evidence: map[string]any{
					"file":    doc.FilePath,
					"line":    1,
					"snippet": "",
				},
				Remediation: "Add a '" + field + "' field to the skill frontmatter.",
			})
		}
	}

	return findings
}

// CheckQA002 checks that the frontmatter name matches the directory name in the file path.
func CheckQA002(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeSkillMD {
		return nil
	}

	fm, _ := doc.Parsed["frontmatter"].(map[string]any)
	name, _ := fm["name"].(string)
	if name == "" {
		return nil
	}

	m := skillNameFromPathRe.FindStringSubmatch(doc.FilePath)
	if m == nil {
		return nil
	}

	dirName := m[1]
	if dirName == name {
		return nil
	}

	return []document.ScanFinding{{
		RuleID:   "QA_002",
		Severity: document.SeverityWarn,
		Message:  fmt.Sprintf("Frontmatter 'name' ('%s') does not match directory name ('%s')", name, dirName),
		Evidence: map[string]any{
			"file":    doc.FilePath,
			"line":    GetFrontmatterLine(doc, "name"),
			"snippet": "name: " + name,
		},
		Remediation: "Set 'name' to match the skill's directory name exactly.",
	}}
}

// CheckQA003 checks that the description is long enough.
func CheckQA003(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeSkillMD {
		return nil
	}

	minLen := getIntParam("QA_003", "min_description_length", 20)

	fm, _ := doc.Parsed["frontmatter"].(map[string]any)
	desc, _ := fm["description"].(string)
	trimmed := strings.TrimSpace(desc)
	if trimmed == "" || len(trimmed) >= minLen {
		return nil
	}

	return []document.ScanFinding{{
		RuleID:   "QA_003",
		Severity: document.SeverityWarn,
		Message:  fmt.Sprintf("Description is too short (%d chars, minimum %d)", len(trimmed), minLen),
		Evidence: map[string]any{
			"file":            doc.FilePath,
			"line":            GetFrontmatterLine(doc, "description"),
			"snippet":         trimmed,
			"measured_length": len(trimmed),
		},
		Remediation: "Provide a longer description so Claude has enough context to auto-invoke the skill.",
	}}
}

// CheckQA004 checks that the skill body is not empty.
func CheckQA004(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeSkillMD {
		return nil
	}

	body, _ := doc.Parsed["body"].(string)
	if strings.TrimSpace(body) != "" {
		return nil
	}

	return []document.ScanFinding{{
		RuleID:   "QA_004",
		Severity: document.SeverityWarn,
		Message:  "Skill body is empty",
		Evidence: map[string]any{
			"file":    doc.FilePath,
			"line":    getBodyOffset(doc) + 1,
			"snippet": "",
		},
		Remediation: "Add instructions to the skill body.",
	}}
}

// stripCodeFences removes fenced code block content, leaving only prose.
// Uses the same fence-tracking logic as the parser's ComputeCodeBlockLines.
func stripCodeFences(text string) string {
	cbl := parser.ComputeCodeBlockLines(text)
	if len(cbl) == 0 {
		return text
	}
	lines := strings.Split(text, "\n")
	var prose []string
	for i, line := range lines {
		if !cbl[i+1] { // cbl is 1-based
			prose = append(prose, line)
		}
	}
	return strings.Join(prose, "\n")
}

// CheckQA005 checks that the skill body (after stripping code blocks) is long enough.
func CheckQA005(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeSkillMD {
		return nil
	}

	body, _ := doc.Parsed["body"].(string)
	if strings.TrimSpace(body) == "" {
		return nil // QA_004 handles empty body
	}

	stripped := stripCodeFences(body)
	if len(strings.TrimSpace(stripped)) >= 50 {
		return nil
	}

	return []document.ScanFinding{{
		RuleID:   "QA_005",
		Severity: document.SeverityInfo,
		Message:  "Skill body is too short after stripping code blocks (less than 50 chars of prose)",
		Evidence: map[string]any{
			"file":    doc.FilePath,
			"line":    getBodyOffset(doc) + 1,
			"snippet": "",
		},
		Remediation: "Add more prose instructions to the skill body.",
	}}
}

// CheckQA006 checks that the skill has a non-empty tools list in frontmatter.
func CheckQA006(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeSkillMD {
		return nil
	}

	fm, _ := doc.Parsed["frontmatter"].(map[string]any)
	tools, exists := fm["tools"]
	if !exists {
		return []document.ScanFinding{{
			RuleID:   "QA_006",
			Severity: document.SeverityInfo,
			Message:  "Missing 'tools' list in frontmatter",
			Evidence: map[string]any{
				"file":    doc.FilePath,
				"line":    1,
				"snippet": "",
			},
			Remediation: "Add a 'tools' list to the frontmatter to declare which tools this skill uses.",
		}}
	}

	toolsList, ok := tools.([]any)
	if !ok || len(toolsList) == 0 {
		return []document.ScanFinding{{
			RuleID:   "QA_006",
			Severity: document.SeverityInfo,
			Message:  "Empty 'tools' list in frontmatter",
			Evidence: map[string]any{
				"file":    doc.FilePath,
				"line":    GetFrontmatterLine(doc, "tools"),
				"snippet": "",
			},
			Remediation: "Add tools to the 'tools' list in the frontmatter.",
		}}
	}

	return nil
}

// CheckQA007 checks that the skill name matches the valid name pattern.
func CheckQA007(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeSkillMD {
		return nil
	}

	fm, _ := doc.Parsed["frontmatter"].(map[string]any)
	name, _ := fm["name"].(string)
	if name == "" {
		return nil
	}

	if validSkillNameRe.MatchString(name) {
		return nil
	}

	return []document.ScanFinding{{
		RuleID:   "QA_007",
		Severity: document.SeverityWarn,
		Message:  fmt.Sprintf("Invalid skill name format: '%s'", name),
		Evidence: map[string]any{
			"file":    doc.FilePath,
			"line":    GetFrontmatterLine(doc, "name"),
			"snippet": "name: " + name,
		},
		Remediation: "Use only lowercase letters, numbers, and hyphens. Name must start with a letter or digit.",
	}}
}

// CheckQA008 checks that the file is not too large. Applies to all file types.
func CheckQA008(doc *document.ConfigDocument) []document.ScanFinding {
	maxKB := getFloatParam("QA_008", "max_file_size_kb", 50.0)
	maxBytes := int(maxKB * 1024)

	if len(doc.Content) <= maxBytes {
		return nil
	}

	sizeKB := float64(len(doc.Content)) / 1024.0
	return []document.ScanFinding{{
		RuleID:   "QA_008",
		Severity: document.SeverityWarn,
		Message:  fmt.Sprintf("File is too large (%.1f KB, >%.1f KB threshold)", sizeKB, maxKB),
		Evidence: map[string]any{
			"file":             doc.FilePath,
			"line":             1,
			"snippet":          "",
			"measured_size_kb": math.Round(sizeKB*10) / 10,
		},
		Remediation: "Review the file for bloat and consider splitting into smaller files.",
	}}
}
