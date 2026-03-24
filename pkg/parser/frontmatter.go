package parser

import (
	"regexp"
	"strings"

	"github.com/bouncerfox/cli/pkg/document"
	"gopkg.in/yaml.v3"
)

var (
	yamlAnchorRe     = regexp.MustCompile(`(?m)^\s*\w+:\s*&\w+`)
	yamlAliasRe      = regexp.MustCompile(`(?m)^\s*\w+:\s*\*\w+`)
	frontmatterKeyRe = regexp.MustCompile(`^([\w][\w-]*):`)
)

const maxContentSize = 512 * 1024 // 512KB
const binaryCheckSize = 8192

func checkBinaryContent(content string) bool {
	check := content
	if len(check) > binaryCheckSize {
		check = check[:binaryCheckSize]
	}
	return strings.Contains(check, "\x00")
}

func computeFrontmatterLines(content string) map[string]int {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return nil
	}
	result := make(map[string]int)
	for i, line := range lines[1:] {
		lineNum := i + 2 // 1-based, starting after first ---
		if strings.TrimSpace(line) == "---" {
			break
		}
		m := frontmatterKeyRe.FindStringSubmatch(line)
		if m != nil {
			result[m[1]] = lineNum
		}
	}
	return result
}

func makeRejectionDoc(fileType, filePath, content, reason string) *document.ConfigDocument {
	truncated := content
	if len(truncated) > 1024 {
		truncated = truncated[:1024]
	}
	return &document.ConfigDocument{
		FileType:    fileType,
		FilePath:    filePath,
		Content:     truncated,
		Parsed:      map[string]any{"_parse_error": true, "_reason": reason},
		ContentHash: ComputeContentHash([]byte(content)),
	}
}

// findClosingFrontmatter finds the closing --- delimiter that starts on its own line.
// Returns the byte offset of the closing --- in content, or -1 if not found.
// The search starts after the opening --- (offset 3+).
func findClosingFrontmatter(content string) int {
	// Skip opening "---" and its trailing newline
	searchStart := 3
	if searchStart < len(content) && content[searchStart] == '\n' {
		searchStart++
	}
	for i := searchStart; i < len(content); i++ {
		// Check for --- at start of a line
		if content[i] == '\n' && i+3 < len(content) &&
			content[i+1] == '-' && content[i+2] == '-' && content[i+3] == '-' {
			// Verify it's --- followed by newline or EOF
			afterDashes := i + 4
			if afterDashes >= len(content) || content[afterDashes] == '\n' {
				return i + 1 // position of the first '-'
			}
		}
	}
	return -1
}

func computeCodeBlockLinesPair(body, content string) (map[int]bool, map[int]bool) {
	if body == content {
		cbl := ComputeCodeBlockLines(content)
		return cbl, cbl
	}
	return ComputeCodeBlockLines(body), ComputeCodeBlockLines(content)
}

// ParseFrontmatterMD parses a markdown file with optional YAML frontmatter.
func ParseFrontmatterMD(fileType, filePath, content string) *document.ConfigDocument {
	if checkBinaryContent(content) {
		return makeRejectionDoc(fileType, filePath, content, "binary_content")
	}
	content = NormalizeContent(content)
	if len(content) > maxContentSize {
		return makeRejectionDoc(fileType, filePath, content, "content_too_large")
	}

	fmLines := computeFrontmatterLines(content)

	var body string
	bodyStartLine := 1
	hasFrontmatter := false
	fmEnd := -1

	if strings.HasPrefix(content, "---") {
		fmEnd = findClosingFrontmatter(content)
		if fmEnd >= 0 {
			hasFrontmatter = true
			bodyStartLine = strings.Count(content[:fmEnd+3], "\n") + 1
		}
	}

	// Check for YAML anchors/aliases before parsing
	if hasFrontmatter {
		fmBlock := content[:fmEnd+3]
		if yamlAnchorRe.MatchString(fmBlock) || yamlAliasRe.MatchString(fmBlock) {
			body = strings.TrimLeft(content[fmEnd+3:], "\n")
			cbl, ccbl := computeCodeBlockLinesPair(body, content)
			return &document.ConfigDocument{
				FileType: fileType,
				FilePath: filePath,
				Content:  content,
				Parsed: map[string]any{
					"_parse_error":             true,
					"_reason":                  "yaml_anchors",
					"frontmatter":              map[string]any{},
					"frontmatter_lines":        fmLines,
					"body":                     body,
					"body_start_line":          bodyStartLine,
					"code_block_lines":         cbl,
					"content_code_block_lines": ccbl,
				},
				ContentHash: ComputeContentHash([]byte(content)),
			}
		}
	}

	// Parse frontmatter
	frontmatter := map[string]any{}
	if hasFrontmatter {
		fmContent := content[4:fmEnd] // between --- delimiters
		if err := yaml.Unmarshal([]byte(fmContent), &frontmatter); err != nil {
			body = content
			bodyStartLine = 1
			cbl := ComputeCodeBlockLines(content)
			return &document.ConfigDocument{
				FileType: fileType,
				FilePath: filePath,
				Content:  content,
				Parsed: map[string]any{
					"_parse_error":             true,
					"frontmatter":              map[string]any{},
					"frontmatter_lines":        fmLines,
					"body":                     body,
					"body_start_line":          bodyStartLine,
					"code_block_lines":         cbl,
					"content_code_block_lines": cbl,
				},
				ContentHash: ComputeContentHash([]byte(content)),
			}
		}
		body = strings.TrimLeft(content[fmEnd+3:], "\n")
	} else {
		body = content
	}

	cbl, ccbl := computeCodeBlockLinesPair(body, content)
	return &document.ConfigDocument{
		FileType: fileType,
		FilePath: filePath,
		Content:  content,
		Parsed: map[string]any{
			"frontmatter":              frontmatter,
			"frontmatter_lines":        fmLines,
			"body":                     body,
			"body_start_line":          bodyStartLine,
			"code_block_lines":         cbl,
			"content_code_block_lines": ccbl,
		},
		ContentHash: ComputeContentHash([]byte(content)),
	}
}

// ParseClaudeMD parses a CLAUDE.md file as plain markdown (no frontmatter).
func ParseClaudeMD(filePath, content string) *document.ConfigDocument {
	if checkBinaryContent(content) {
		return makeRejectionDoc(document.FileTypeClaudeMD, filePath, content, "binary_content")
	}
	content = NormalizeContent(content)
	if len(content) > maxContentSize {
		return makeRejectionDoc(document.FileTypeClaudeMD, filePath, content, "content_too_large")
	}

	codeBlockLines := ComputeCodeBlockLines(content)
	return &document.ConfigDocument{
		FileType: document.FileTypeClaudeMD,
		FilePath: filePath,
		Content:  content,
		Parsed: map[string]any{
			"body":                     content,
			"body_start_line":          1,
			"code_block_lines":         codeBlockLines,
			"content_code_block_lines": codeBlockLines,
		},
		ContentHash: ComputeContentHash([]byte(content)),
	}
}
