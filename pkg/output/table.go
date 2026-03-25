// Package output provides formatters for scan findings: table, JSON, and SARIF.
package output

import (
	"fmt"
	"io"

	"github.com/bouncerfox/cli/pkg/document"
)

// ANSI color codes.
const (
	ansiReset    = "\033[0m"
	ansiBold     = "\033[1m"
	ansiRed      = "\033[31m"
	ansiRedBold  = "\033[1;31m"
	ansiYellow   = "\033[33m"
	ansiCyan     = "\033[36m"
)

func severityColor(s document.FindingSeverity) string {
	switch s {
	case document.SeverityCritical:
		return ansiRedBold
	case document.SeverityHigh:
		return ansiRed
	case document.SeverityWarn:
		return ansiYellow
	case document.SeverityInfo:
		return ansiCyan
	default:
		return ""
	}
}

// FormatTable writes human-readable, ANSI-colored output to w.
//
// Each finding is rendered as:
//
//	[severity] rule_id: message
//	  → file:line
//	  → remediation
//
// A summary line is appended at the end.
func FormatTable(findings []document.ScanFinding, w io.Writer) error {
	counts := map[document.FindingSeverity]int{}

	for _, f := range findings {
		counts[f.Severity]++
		color := severityColor(f.Severity)
		file, line := evidenceFileAndLine(f.Evidence)

		// Header line: [severity] rule_id: message
		if _, err := fmt.Fprintf(w, "%s[%s]%s %s: %s\n",
			color, f.Severity, ansiReset, f.RuleID, f.Message); err != nil {
			return err
		}

		// Location
		if file != "" {
			if line > 0 {
				if _, err := fmt.Fprintf(w, "  \u2192 %s:%d\n", file, line); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(w, "  \u2192 %s\n", file); err != nil {
					return err
				}
			}
		}

		// Remediation
		if f.Remediation != "" {
			if _, err := fmt.Fprintf(w, "  \u2192 %s\n", f.Remediation); err != nil {
				return err
			}
		}
	}

	// Summary line.
	total := len(findings)
	_, err := fmt.Fprintf(w, "\nFound %d finding(s) (%d critical, %d high, %d warn, %d info)\n",
		total,
		counts[document.SeverityCritical],
		counts[document.SeverityHigh],
		counts[document.SeverityWarn],
		counts[document.SeverityInfo],
	)
	return err
}

// evidenceFileAndLine extracts file and line from an evidence map.
func evidenceFileAndLine(ev map[string]any) (file string, line int) {
	if ev == nil {
		return "", 0
	}
	if v, ok := ev["file"]; ok {
		file, _ = v.(string)
	}
	switch v := ev["line"].(type) {
	case int:
		line = v
	case float64:
		line = int(v)
	case int64:
		line = int(v)
	}
	return file, line
}
