package output

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bouncerfox/cli/pkg/document"
)

const codeFrameContext = 2

// maskedRules are rule IDs whose finding lines should be fully masked.
var maskedRules = map[string]bool{
	"SEC_001": true,
	"SEC_018": true,
}

// writeCodeFrame reads the source file and writes a code frame around the
// finding line. If the file is missing or the line is out of range, it
// silently does nothing.
func writeCodeFrame(w io.Writer, rm renderMode, f document.ScanFinding) {
	file, line := evidenceFileAndLine(f.Evidence)
	if file == "" || line <= 0 {
		return
	}

	lines, err := readFileLines(file)
	if err != nil {
		return
	}
	if line > len(lines) {
		return
	}

	startLine := line - codeFrameContext
	if startLine < 1 {
		startLine = 1
	}
	endLine := line + codeFrameContext
	if endLine > len(lines) {
		endLine = len(lines)
	}

	gutterWidth := len(fmt.Sprintf("%d", endLine))
	maskLine := maskedRules[f.RuleID]

	_, _ = fmt.Fprintln(w, rm.boxTop())
	for i := startLine; i <= endLine; i++ {
		content := sanitizeForDisplay(lines[i-1])
		if maskLine && i == line {
			content = strings.Repeat("*", min(len(content), 40))
		}
		_, _ = fmt.Fprintf(w, "%s %*d  %s\n", rm.boxLine(), gutterWidth, i, content)
	}
	_, _ = fmt.Fprintln(w, rm.boxBottom())
}

func readFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
