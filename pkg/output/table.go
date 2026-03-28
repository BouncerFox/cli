// Package output provides formatters for scan findings: table, JSON, and SARIF.
package output

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bouncerfox/cli/pkg/document"
)

// ANSI color codes used by table.go and display.go.
const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiRed     = "\033[31m"
	ansiRedBold = "\033[1;31m"
	ansiYellow  = "\033[33m"
	ansiCyan    = "\033[36m"
)

// FormatOptions controls how FormatTable renders output.
type FormatOptions struct {
	Verbose  bool
	NoColor  bool
	IsTTY    bool
	ScanRoot string
	Stats    ScanStats
}

// ScanStats holds performance and coverage stats for the summary banner.
type ScanStats struct {
	FilesScanned int
	RulesRun     int
	Skipped      int
	Duration     time.Duration
}

// FormatTable writes human-readable output to w, grouped by file, with a
// summary banner. Colour and Unicode are enabled only when opts.IsTTY is true
// and opts.NoColor is false.
func FormatTable(findings []document.ScanFinding, w io.Writer, opts FormatOptions) error {
	rm := resolveRenderMode(opts.NoColor, opts.IsTTY)

	// Group findings by file, preserving insertion order per file via a slice.
	type entry struct {
		finding document.ScanFinding
		line    int
	}
	type group struct {
		file    string
		entries []entry
	}

	fileIndex := map[string]int{}
	var groups []group

	for _, f := range findings {
		file, line := evidenceFileAndLine(f.Evidence)
		if file == "" {
			file = "(unknown)"
		}
		rel := relPath(opts.ScanRoot, file)

		idx, exists := fileIndex[rel]
		if !exists {
			idx = len(groups)
			fileIndex[rel] = idx
			groups = append(groups, group{file: rel})
		}
		groups[idx].entries = append(groups[idx].entries, entry{finding: f, line: line})
	}

	// Sort groups alphabetically by file name.
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].file < groups[j].file
	})

	// Count severities.
	counts := map[document.FindingSeverity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	// Render each file group.
	for _, g := range groups {
		if _, err := fmt.Fprintf(w, "%s\n", rm.bold(g.file)); err != nil {
			return err
		}
		for _, e := range g.entries {
			f := e.finding
			badge := rm.severityBadge(string(f.Severity))
			lineStr := ""
			if e.line > 0 {
				lineStr = fmt.Sprintf(":%d", e.line)
			}
			if _, err := fmt.Fprintf(w, "  %-12s  %-8s  %-52s%s\n",
				badge, f.RuleID, f.Message, lineStr); err != nil {
				return err
			}
			if f.Remediation != "" {
				if _, err := fmt.Fprintf(w, "              %s %s\n",
					rm.arrow(), f.Remediation); err != nil {
					return err
				}
			}
			if opts.Verbose {
				writeCodeFrame(w, rm, f)
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}

	// Summary banner.
	total := len(findings)
	if total == 0 {
		stats := formatStats(rm, opts.Stats)
		if _, err := fmt.Fprintf(w, "  %s  No findings %s %s\n",
			rm.passBadge(), rm.dot(), stats); err != nil {
			return err
		}
	} else {
		sevParts := buildSevParts(counts)
		filesHit := len(groups)
		fileWord := "file"
		if filesHit != 1 {
			fileWord = "files"
		}
		findingWord := "findings"
		if total == 1 {
			findingWord = "finding"
		}
		summary := fmt.Sprintf("%d %s in %d %s", total, findingWord, filesHit, fileWord)
		if len(sevParts) > 0 {
			summary += "  (" + strings.Join(sevParts, ", ") + ")"
		}
		if _, err := fmt.Fprintf(w, "  %s  %s\n", rm.failBadge(), summary); err != nil {
			return err
		}
		stats := formatStats(rm, opts.Stats)
		if _, err := fmt.Fprintf(w, "          %s\n", stats); err != nil {
			return err
		}
	}

	return nil
}

// buildSevParts builds the non-zero severity count parts for the summary.
func buildSevParts(counts map[document.FindingSeverity]int) []string {
	order := []document.FindingSeverity{
		document.SeverityCritical,
		document.SeverityHigh,
		document.SeverityWarn,
		document.SeverityInfo,
	}
	var parts []string
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, string(sev)))
		}
	}
	return parts
}

// formatStats returns the stats line text.
func formatStats(rm renderMode, s ScanStats) string {
	dot := rm.dot()
	dur := formatDuration(s.Duration)
	return fmt.Sprintf("%d files scanned %s %d rules %s %d skipped %s %s",
		s.FilesScanned, dot, s.RulesRun, dot, s.Skipped, dot, dur)
}

// formatDuration formats a duration as a short decimal string (e.g. "0.02s").
func formatDuration(d time.Duration) string {
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// relPath returns a path relative to root, or the original path if
// Rel fails or root is empty.
func relPath(root, file string) string {
	if root == "" {
		return file
	}
	rel, err := filepath.Rel(root, file)
	if err != nil {
		return file
	}
	return rel
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

