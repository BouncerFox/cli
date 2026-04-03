// Package engine orchestrates the scan of ConfigDocuments against the rule
// registry, applying suppression, severity floors, deduplication, and caps.
package engine

import (
	"context"
	"fmt"

	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/fingerprint"
	"github.com/bouncerfox/cli/pkg/rules"
)

// CustomCheck represents a compiled custom rule that runs alongside built-in rules.
type CustomCheck struct {
	RuleID      string
	Name        string
	Severity    document.FindingSeverity
	FileTypes   []string
	Remediation string
	Check       func(*document.ConfigDocument) []document.ScanFinding
}

// ScanOptions controls how the engine behaves for a given scan.
type ScanOptions struct {
	// EnabledRules restricts the scan to only these rule IDs.
	// An empty slice means all rules are enabled.
	EnabledRules []string

	// DisabledRules skips these rule IDs even if they appear in EnabledRules.
	DisabledRules []string

	// SeverityFloor suppresses any finding whose severity is lower than this
	// value. Zero value (empty string) means no floor.
	SeverityFloor document.FindingSeverity

	// SeverityOverrides remaps per-rule severity after check functions run.
	SeverityOverrides map[string]document.FindingSeverity

	// MaxFindings caps the total number of findings returned. 0 = unlimited.
	MaxFindings int

	// RuleParams holds per-rule parameter overrides for this scan.
	// If nil, rules use their compiled defaults.
	RuleParams map[string]map[string]any

	// SuppressionMap is a set of fingerprints to skip. A finding whose
	// fingerprint is in this map is not included in the result.
	SuppressionMap map[string]bool

	// FileTypeOverrides narrows per-rule file type applicability. When set for
	// a rule, only the listed file types are scanned (must be a subset of the
	// rule's DefaultFileTypes).
	FileTypeOverrides map[string][]string

	// CustomChecks holds compiled custom rules from the platform.
	CustomChecks []CustomCheck
}

// ruleSuppressionMap defines which rules suppress other rules on the same
// file+line. When a suppressor rule fires on a line, suppressee rules'
// findings on that same line are dropped.
var ruleSuppressionMap = map[string][]string{
	"SEC_001": {"SEC_018", "SEC_006"},
	"SEC_018": {"SEC_006"},
	"SEC_007": {"SEC_006"},
}

// ScanResult holds the output of a Scan call.
type ScanResult struct {
	Findings     []document.ScanFinding
	FilesScanned int
	RulesRun     int
}

// locationKey builds a key for rule-to-rule suppression lookups.
func locationKey(filePath string, line any) string {
	return filePath + ":" + fmt.Sprint(line)
}

// safeCheck wraps a check function with panic recovery. If the check panics,
// a synthetic warning finding is returned instead of crashing.
func safeCheck(ruleID string, filePath string, checkFn func() []document.ScanFinding) (findings []document.ScanFinding, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			findings = []document.ScanFinding{{
				RuleID:   ruleID,
				Severity: document.SeverityWarn,
				Message:  fmt.Sprintf("rule failed to execute (panic recovered: %v)", r),
				Evidence: map[string]any{
					"file": filePath,
				},
			}}
			panicked = true
		}
	}()
	return checkFn(), false
}

// Scan runs all applicable rules from rules.Registry against each document in
// docs, then applies rule-to-rule suppression, severity overrides, severity
// floor, deduplication, and caps.
func Scan(ctx context.Context, docs []*document.ConfigDocument, opts ScanOptions) ScanResult {
	enabledSet := makeStringSet(opts.EnabledRules)
	disabledSet := makeStringSet(opts.DisabledRules)

	rulesRunSet := make(map[string]bool)
	rc := &document.RuleContext{Ctx: ctx, Params: opts.RuleParams}

	// Phase 1: Run all rules, collect raw findings per document.
	type rawFinding struct {
		finding document.ScanFinding
		fp      string
	}
	var rawFindings []rawFinding
	filesScanned := 0

	for _, doc := range docs {
		if doc == nil {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		filesScanned++
		// Track which rule fired on which file+line for suppression.
		// Key: "file:line", Value: set of rule IDs that fired there.
		firedAt := make(map[string]map[string]bool)

		var docFindings []rawFinding

		for i := range rules.Registry {
			rule := &rules.Registry[i]

			applicableTypes := rule.DefaultFileTypes
			if override, ok := opts.FileTypeOverrides[rule.ID]; ok {
				applicableTypes = override
			}
			if !fileTypeApplies(applicableTypes, doc.FileType) {
				continue
			}
			if len(enabledSet) > 0 && !enabledSet[rule.ID] {
				continue
			}
			if disabledSet[rule.ID] {
				continue
			}
			if rule.Check == nil {
				continue
			}
			if ctx.Err() != nil {
				break
			}

			rulesRunSet[rule.ID] = true
			findings, _ := safeCheck(rule.ID, doc.FilePath, func() []document.ScanFinding { return rule.Check(doc, rc) })

			for _, f := range findings {
				// Apply severity override if configured.
				if sev, ok := opts.SeverityOverrides[f.RuleID]; ok {
					f.Severity = sev
				}

				fp := fingerprint.ComputeFingerprint(f)

				// Record where this rule fired for suppression.
				loc := locationKey(doc.FilePath, f.Evidence["line"])
				if firedAt[loc] == nil {
					firedAt[loc] = make(map[string]bool)
				}
				firedAt[loc][f.RuleID] = true

				docFindings = append(docFindings, rawFinding{f, fp})
			}
		}

		// Run custom checks from the platform.
		for i := range opts.CustomChecks {
			cc := &opts.CustomChecks[i]
			if !fileTypeApplies(cc.FileTypes, doc.FileType) {
				continue
			}
			if disabledSet[cc.RuleID] {
				continue
			}
			if cc.Check == nil {
				continue
			}
			if ctx.Err() != nil {
				break
			}

			rulesRunSet[cc.RuleID] = true
			findings, _ := safeCheck(cc.RuleID, doc.FilePath, func() []document.ScanFinding { return cc.Check(doc) })

			for _, f := range findings {
				if sev, ok := opts.SeverityOverrides[f.RuleID]; ok {
					f.Severity = sev
				}
				fp := fingerprint.ComputeFingerprint(f)
				loc := locationKey(doc.FilePath, f.Evidence["line"])
				if firedAt[loc] == nil {
					firedAt[loc] = make(map[string]bool)
				}
				firedAt[loc][f.RuleID] = true
				docFindings = append(docFindings, rawFinding{f, fp})
			}
		}

		// Phase 2: Apply rule-to-rule suppression within this document.
		for _, rf := range docFindings {
			loc := locationKey(doc.FilePath, rf.finding.Evidence["line"])
			suppressed := false
			for suppressorRule, suppressees := range ruleSuppressionMap {
				if firedAt[loc][suppressorRule] {
					for _, suppressee := range suppressees {
						if rf.finding.RuleID == suppressee {
							suppressed = true
							break
						}
					}
				}
				if suppressed {
					break
				}
			}
			if !suppressed {
				rawFindings = append(rawFindings, rf)
			}
		}
	}

	// Phase 3: Apply severity floor, fingerprint suppression, dedup, cap.
	seen := make(map[string]bool)
	allFindings := make([]document.ScanFinding, 0, len(rawFindings))

	for _, rf := range rawFindings {
		if opts.SuppressionMap[rf.fp] {
			continue
		}
		if opts.SeverityFloor != "" && rf.finding.Severity.Level() < opts.SeverityFloor.Level() {
			continue
		}
		if seen[rf.fp] {
			continue
		}
		seen[rf.fp] = true

		allFindings = append(allFindings, rf.finding)

		if opts.MaxFindings > 0 && len(allFindings) >= opts.MaxFindings {
			break
		}
	}

	return ScanResult{
		Findings:     allFindings,
		FilesScanned: filesScanned,
		RulesRun:     len(rulesRunSet),
	}
}

// fileTypeApplies returns true if fileType appears in the applicableTypes slice.
// An empty applicableTypes slice is treated as "all file types".
func fileTypeApplies(applicableTypes []string, fileType string) bool {
	if len(applicableTypes) == 0 {
		return true
	}
	for _, t := range applicableTypes {
		if t == fileType {
			return true
		}
	}
	return false
}

// makeStringSet converts a slice of strings to a boolean lookup map.
func makeStringSet(ss []string) map[string]bool {
	if len(ss) == 0 {
		return nil
	}
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}
