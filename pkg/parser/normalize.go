package parser

import (
	"html"

	"golang.org/x/text/unicode/norm"
)

// NormalizeContent applies Unicode NFKC normalization and HTML entity unescaping.
// This prevents scanner bypass via fullwidth characters (e.g., ｒｍ → rm) or
// HTML entities (e.g., &lt; → <).
func NormalizeContent(content string) string {
	if !norm.NFKC.IsNormalString(content) {
		content = norm.NFKC.String(content)
	}
	content = html.UnescapeString(content)
	return content
}
