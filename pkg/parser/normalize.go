package parser

import (
	"html"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// NormalizeContent applies Unicode NFKC normalization, HTML entity unescaping,
// and canonical LF line endings. This prevents scanner bypass via fullwidth
// characters (e.g., ｒｍ → rm) or HTML entities (e.g., &lt; → <), and keeps
// parsing and content hashes stable across operating systems.
func NormalizeContent(content string) string {
	if !norm.NFKC.IsNormalString(content) {
		content = norm.NFKC.String(content)
	}
	content = html.UnescapeString(content)
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	return content
}
