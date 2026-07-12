package parser

import "github.com/bouncerfox/cli/pkg/document"

// Stable parser rejection reasons. Callers may map these identifiers to
// human-readable diagnostics without exposing input content or parser errors.
const (
	RejectionReasonInvalidYAML     = "invalid_yaml"
	RejectionReasonInvalidJSON     = "invalid_json"
	RejectionReasonYAMLReferences  = "yaml_anchors"
	RejectionReasonContentTooLarge = "content_too_large"
)

// RejectionDetails returns safe, stable metadata for a document rejected by a
// parser. The line defaults to 1 when the parser cannot safely identify a more
// precise location.
func RejectionDetails(doc *document.ConfigDocument) (reason string, line int, rejected bool) {
	if doc == nil || doc.Parsed == nil {
		return "", 0, false
	}
	parseError, _ := doc.Parsed["_parse_error"].(bool)
	if !parseError {
		return "", 0, false
	}
	reason, _ = doc.Parsed["_reason"].(string)
	line, _ = doc.Parsed["_rejection_line"].(int)
	if line < 1 {
		line = 1
	}
	return reason, line, true
}
