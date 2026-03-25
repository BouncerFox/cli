package parser

import (
	"regexp"
	"strings"
)

var fenceRe = regexp.MustCompile(`^(` + "`{3,}" + `|~{3,})`)

// ComputeCodeBlockLines returns a set of 1-based line numbers that fall inside
// fenced code blocks. Fence lines themselves (opening/closing) are NOT included
// — only content lines between fences. Unclosed fences include all remaining lines.
func ComputeCodeBlockLines(text string) map[int]bool {
	result := make(map[int]bool)
	if text == "" {
		return result
	}

	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	inFence := false
	fenceChar := byte(0)
	fenceLen := 0

	for i, line := range lines {
		stripped := strings.TrimLeft(line, " \t")
		if !inFence {
			m := fenceRe.FindString(stripped)
			if m != "" {
				inFence = true
				fenceChar = m[0]
				fenceLen = len(m)
			}
		} else {
			if stripped != "" && stripped[0] == fenceChar {
				m := fenceRe.FindString(stripped)
				if m != "" && len(m) >= fenceLen && strings.TrimRight(stripped, " \t") == m {
					inFence = false
					continue
				}
			}
			result[i+1] = true // 1-based
		}
	}

	return result
}
