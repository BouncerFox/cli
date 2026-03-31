package parser

import (
	"encoding/json"
	"strings"

	"github.com/bouncerfox/cli/pkg/document"
)

const maxJSONDepth = 10

func checkJSONDepth(content string) bool {
	depth := 0
	inString := false
	escape := false
	for i := 0; i < len(content); i++ {
		ch := content[i]
		if escape {
			escape = false
			continue
		}
		if ch == '\\' {
			if inString {
				escape = true
			}
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch ch {
		case '{', '[':
			depth++
			if depth > maxJSONDepth {
				return true
			}
		case '}', ']':
			depth--
		}
	}
	return false
}

// FindJSONKeyLine returns the 1-based line number where a JSON key first appears.
// Returns 1 if not found.
func FindJSONKeyLine(content, key string) int {
	needle := `"` + key + `"`
	for i, line := range strings.Split(content, "\n") {
		idx := strings.Index(line, needle)
		if idx >= 0 && strings.Contains(line[idx:], ":") {
			return i + 1
		}
	}
	return 1
}

// ParseJSONConfig parses a JSON config file (settings.json, .mcp.json).
func ParseJSONConfig(fileType, filePath, content string) *document.ConfigDocument {
	if checkBinaryContent(content) {
		return makeRejectionDoc(fileType, filePath, content, "binary_content")
	}
	content = NormalizeContent(content)
	if len(content) > maxContentSize {
		return makeRejectionDoc(fileType, filePath, content, "content_too_large")
	}
	if checkJSONDepth(content) {
		return makeRejectionDoc(fileType, filePath, content, "json_nesting_depth")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		parsed = map[string]any{"_parse_error": true}
	}

	return &document.ConfigDocument{
		FileType:    fileType,
		FilePath:    filePath,
		Content:     content,
		Parsed:      parsed,
		ContentHash: ComputeContentHash([]byte(content)),
	}
}
