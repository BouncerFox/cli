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
	Verbose   bool
	NoColor   bool
	IsTTY     bool
	ScanRoot  string
	Stats     ScanStats
	GroupBy   string            // "file" (default), "rule", or "severity"
	RuleNames map[string]string // ruleID -> human-readable name (used by group-by-rule)
}

// ScanStats holds performance and coverage stats for the summary banner.
type ScanStats struct {
	FilesScanned int
	RulesRun     int
	Skipped      int
	Duration     time.Duration
}

// entry holds a single finding with its extracted file path and line number.
type entry struct {
	finding document.ScanFinding
	file    string
	line    int
}

// group holds a set of findings sharing a common grouping key.
type group struct {
	key     string // grouping key (file path, rule ID, or severity)
	label   string // display label for the header
	entries []entry
}

// severityOrder maps severity strings to sort positions (lower = higher priority).
var severityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"warn":     2,
	"info":     3,
}

// FormatTable writes human-readable output to w, grouped according to
// opts.GroupBy (file, rule, or severity), with a summary banner. Colour and
// Unicode are enabled only when opts.IsTTY is true and opts.NoColor is false.
func FormatTable(findings []document.ScanFinding, w io.Writer, opts FormatOptions) error {
	rm := resolveRenderMode(opts.NoColor, opts.IsTTY)
	mode := opts.GroupBy
	if mode == "" {
		mode = "file"
	}

	// Build entries with extracted file and line.
	entries := make([]entry, 0, len(findings))
	for _, f := range findings {
		file, line := evidenceFileAndLine(f.Evidence)
		if file == "" {
			file = "(unknown)"
		}
		entries = append(entries, entry{
			finding: f,
			file:    relPath(opts.ScanRoot, file),
			line:    line,
		})
	}

	// Build groups based on mode.
	groups := buildGroups(entries, mode, opts.RuleNames)

	// Sort groups based on mode.
	sortGroups(groups, mode)

	// Count severities for summary.
	counts := map[document.FindingSeverity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	// Render each group.
	for _, g := range groups {
		countWord := "findings"
		if len(g.entries) == 1 {
			countWord = "finding"
		}
		header := fmt.Sprintf("%s (%d %s)", g.label, len(g.entries), countWord)
		if _, err := fmt.Fprintf(w, "%s\n", rm.bold(header)); err != nil {
			return err
		}
		for _, e := range g.entries {
			if err := writeEntry(w, rm, e, mode, opts.Verbose); err != nil {
				return err
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
		sevParts := buildSevParts(rm, counts)
		filesHit := countUniqueFiles(entries)
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

// buildGroups partitions entries into groups based on mode.
func buildGroups(entries []entry, mode string, ruleNames map[string]string) []group {
	index := map[string]int{}
	var groups []group

	for _, e := range entries {
		var key, label string
		switch mode {
		case "rule":
			key = e.finding.RuleID
			label = e.finding.RuleID
			if name, ok := ruleNames[key]; ok && name != "" {
				label = key + " " + name
			}
		case "severity":
			key = string(e.finding.Severity)
			label = key
		default: // "file"
			key = e.file
			label = e.file
		}

		idx, exists := index[key]
		if !exists {
			idx = len(groups)
			index[key] = idx
			groups = append(groups, group{key: key, label: label})
		}
		groups[idx].entries = append(groups[idx].entries, e)
	}

	return groups
}

// severityUnknown is the sort position for unrecognized severity values.
const severityUnknown = 999

// sortGroups sorts groups in-place based on mode.
func sortGroups(groups []group, mode string) {
	switch mode {
	case "severity":
		// Fixed order: critical, high, warn, info.
		sort.SliceStable(groups, func(i, j int) bool {
			oi := severityOrder[groups[i].key]
			oj := severityOrder[groups[j].key]
			return oi < oj
		})
		sortGroupEntries(groups)
	case "rule":
		// Sort by highest severity among the rule's findings, then by rule ID.
		sort.SliceStable(groups, func(i, j int) bool {
			si := highestSeverity(groups[i].entries)
			sj := highestSeverity(groups[j].entries)
			if si != sj {
				return si < sj
			}
			return groups[i].key < groups[j].key
		})
		sortGroupEntries(groups)
	default: // "file"
		sort.SliceStable(groups, func(i, j int) bool {
			return groups[i].key < groups[j].key
		})
	}
}

// sortGroupEntries sorts entries within each group by file path then line number.
func sortGroupEntries(groups []group) {
	for i := range groups {
		sort.SliceStable(groups[i].entries, func(a, b int) bool {
			ea, eb := groups[i].entries[a], groups[i].entries[b]
			if ea.file != eb.file {
				return ea.file < eb.file
			}
			return ea.line < eb.line
		})
	}
}

// highestSeverity returns the best (lowest) severity order among entries.
func highestSeverity(entries []entry) int {
	best := severityUnknown
	for _, e := range entries {
		if o, ok := severityOrder[string(e.finding.Severity)]; ok && o < best {
			best = o
		}
	}
	return best
}

// writeEntry writes a single finding line. The format varies by grouping mode.
func writeEntry(w io.Writer, rm renderMode, e entry, mode string, verbose bool) error {
	f := e.finding
	badge := rm.severityBadge(string(f.Severity))
	fileLine := e.file
	if e.line > 0 {
		fileLine = fmt.Sprintf("%s:%d", e.file, e.line)
	}

	var err error
	switch mode {
	case "rule":
		// badge  file:line  message
		if _, err = fmt.Fprintf(w, "  %-12s  %-30s  %s\n",
			badge, fileLine, f.Message); err != nil {
			return err
		}
	case "severity":
		// badge  ruleID  file:line  message
		if _, err = fmt.Fprintf(w, "  %-12s  %-8s  %-30s  %s\n",
			badge, f.RuleID, fileLine, f.Message); err != nil {
			return err
		}
	default: // "file"
		// badge  ruleID  message  :line
		lineStr := ""
		if e.line > 0 {
			lineStr = fmt.Sprintf(":%d", e.line)
		}
		if _, err = fmt.Fprintf(w, "  %-12s  %-8s  %-52s%s\n",
			badge, f.RuleID, f.Message, lineStr); err != nil {
			return err
		}
	}

	if verbose && f.Remediation != "" {
		if _, err = fmt.Fprintf(w, "              %s %s\n",
			rm.arrow(), f.Remediation); err != nil {
			return err
		}
	}
	if verbose {
		writeCodeFrame(w, rm, f)
	}
	return nil
}

// countUniqueFiles returns the number of distinct files in entries.
func countUniqueFiles(entries []entry) int {
	seen := map[string]struct{}{}
	for _, e := range entries {
		seen[e.file] = struct{}{}
	}
	return len(seen)
}

// severityColor returns the ANSI color code for a severity level.
func severityColor(sev document.FindingSeverity) string {
	switch sev {
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

// buildSevParts builds the non-zero severity count parts for the summary,
// coloring each count with its severity color when rendering allows it.
func buildSevParts(rm renderMode, counts map[document.FindingSeverity]int) []string {
	order := []document.FindingSeverity{
		document.SeverityCritical,
		document.SeverityHigh,
		document.SeverityWarn,
		document.SeverityInfo,
	}
	var parts []string
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			part := fmt.Sprintf("%d %s", n, string(sev))
			if code := severityColor(sev); code != "" {
				part = rm.color(code, part)
			}
			parts = append(parts, part)
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
