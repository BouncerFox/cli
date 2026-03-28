package rules

import (
	"regexp"
	"strings"

	"github.com/bouncerfox/cli/pkg/document"
)

var importLineRe = regexp.MustCompile(`^@(\S+)`)

var dangerousImportPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.\./`),
	regexp.MustCompile(`^/`),
	regexp.MustCompile(`^~/`),
	regexp.MustCompile(`(?i)\$HOME`),
	regexp.MustCompile(`(?i)\.(credentials|env|secrets|tokens)`),
}

// CheckSEC021 detects dangerous @import references in markdown config files.
// Only flags imports with path traversal, absolute paths, home directory, or
// references to known sensitive file patterns. Benign imports are not flagged.
func CheckSEC021(doc *document.ConfigDocument, rc *document.RuleContext) []document.ScanFinding {
	lines := strings.Split(doc.Content, "\n")
	var findings []document.ScanFinding

	for i, line := range lines {
		lineNum := i + 1
		m := importLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		importPath := m[1]

		isDangerous := false
		for _, pat := range dangerousImportPatterns {
			if pat.MatchString(importPath) {
				isDangerous = true
				break
			}
		}
		if !isDangerous {
			continue
		}

		findings = append(findings, document.ScanFinding{
			RuleID:   "SEC_021",
			Severity: document.SeverityHigh,
			Message:  "Dangerous @import references content outside the project or at a sensitive path",
			Evidence: map[string]any{
				"file":    doc.FilePath,
				"line":    lineNum,
				"snippet": truncSnippet(line, 100),
			},
			Remediation: "Remove the dangerous import. Do not import files outside the project directory or from sensitive locations.",
		})
	}
	return findings
}
