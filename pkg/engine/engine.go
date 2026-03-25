// Package engine orchestrates the scan of ConfigDocuments against the rule
// registry, applying suppression, severity floors, deduplication, and caps.
package engine

import (
	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/fingerprint"
	"github.com/bouncerfox/cli/pkg/rules"
)

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

	// MaxFindings caps the total number of findings returned. 0 = unlimited.
	MaxFindings int

	// SuppressionMap is a set of fingerprints to skip. A finding whose
	// fingerprint is in this map is not included in the result.
	SuppressionMap map[string]bool
}

// ScanResult holds the output of a Scan call.
type ScanResult struct {
	Findings     []document.ScanFinding
	FilesScanned int
	RulesRun     int
}

// Scan runs all applicable rules from rules.Registry against each document in
// docs, then applies suppression, severity filtering, deduplication, and caps.
func Scan(docs []*document.ConfigDocument, opts ScanOptions) ScanResult {
	enabledSet := makeStringSet(opts.EnabledRules)
	disabledSet := makeStringSet(opts.DisabledRules)

	seen := make(map[string]bool)
	var allFindings []document.ScanFinding
	rulesRunSet := make(map[string]bool)

	for _, doc := range docs {
		for i := range rules.Registry {
			rule := &rules.Registry[i]

			// Skip rules not applicable to this file type.
			if !fileTypeApplies(rule.DefaultFileTypes, doc.FileType) {
				continue
			}

			// Apply enabled/disabled filters.
			if len(enabledSet) > 0 && !enabledSet[rule.ID] {
				continue
			}
			if disabledSet[rule.ID] {
				continue
			}

			if rule.Check == nil {
				continue
			}

			rulesRunSet[rule.ID] = true
			findings := rule.Check(doc)

			for _, f := range findings {
				// Compute fingerprint for suppression and dedup.
				fp := fingerprint.ComputeFingerprint(f)

				// Skip suppressed fingerprints.
				if opts.SuppressionMap[fp] {
					continue
				}

				// Apply severity floor.
				if opts.SeverityFloor != "" && f.Severity.Level() < opts.SeverityFloor.Level() {
					continue
				}

				// Deduplicate by fingerprint.
				if seen[fp] {
					continue
				}
				seen[fp] = true

				allFindings = append(allFindings, f)

				// Apply max findings cap.
				if opts.MaxFindings > 0 && len(allFindings) >= opts.MaxFindings {
					return ScanResult{
						Findings:     allFindings,
						FilesScanned: len(docs),
						RulesRun:     len(rulesRunSet),
					}
				}
			}
		}
	}

	return ScanResult{
		Findings:     allFindings,
		FilesScanned: len(docs),
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
