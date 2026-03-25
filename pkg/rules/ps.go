package rules

import (
	"github.com/bouncerfox/cli/pkg/document"
)

// CheckPS004 detects hidden instructions in HTML comments in markdown files.
func CheckPS004(doc *document.ConfigDocument) []document.ScanFinding {
	switch doc.FileType {
	case document.FileTypeSkillMD, document.FileTypeClaudeMD, document.FileTypeAgentMD:
		// applicable
	default:
		return nil
	}

	minLen := getIntParam("PS_004", "min_comment_length", 25)

	body, _ := doc.Parsed["body"].(string)
	if body == "" {
		body = doc.Content
	}

	findings := FindHTMLComments(
		body,
		doc,
		"PS_004",
		document.SeverityWarn,
		"Hidden instruction in HTML comment",
		"Review HTML comments for hidden instructions and remove if suspicious.",
		minLen,
	)

	findings = append(findings, FindUnclosedHTMLComments(
		body,
		doc,
		"PS_004",
		document.SeverityWarn,
	)...)

	return findings
}
