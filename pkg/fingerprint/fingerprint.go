// Package fingerprint computes content-stable SHA-256 fingerprints for scan
// findings. Fingerprints are used for suppression and dedup across baseline
// scans. They must not change when a finding moves to a different line number.
package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/bouncerfox/cli/pkg/document"
)

// positionalFields are excluded from the sorted-fallback hash because they
// change when code is edited without the finding itself changing.
var positionalFields = map[string]bool{
	"file":        true,
	"line":        true,
	"line_number": true,
}

// ComputeFingerprint returns the hex-encoded SHA-256 fingerprint for finding.
//
// Component priority:
//  1. rule_id — always included.
//  2. evidence["file"] — file path, always included (prevents cross-file collision).
//  3. evidence["snippet"] — if non-empty.
//  4. evidence["key"] or evidence["field"] — if present.
//  5. Sorted remaining evidence key=value pairs, positional fields excluded.
func ComputeFingerprint(finding document.ScanFinding) string {
	filePath := ""
	if finding.Evidence != nil {
		if v, ok := finding.Evidence["file"]; ok {
			if s, _ := v.(string); s != "" {
				filePath = s
			}
		}
	}

	components := []string{finding.RuleID, filePath}
	components = append(components, stableEvidence(finding.Evidence))
	raw := strings.Join(components, "|")
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

// stableEvidence extracts the stable (non-positional) portion of evidence.
func stableEvidence(evidence map[string]any) string {
	if evidence == nil {
		return ""
	}

	if v, ok := evidence["snippet"]; ok {
		if s, _ := v.(string); s != "" {
			return s
		}
	}

	if v, ok := evidence["key"]; ok {
		return fmt.Sprintf("%v", v)
	}

	if v, ok := evidence["field"]; ok {
		return fmt.Sprintf("%v", v)
	}

	// Fallback: sorted key=value pairs, positional fields excluded.
	type kv struct{ k, v string }
	pairs := make([]kv, 0, len(evidence))
	for k, v := range evidence {
		if !positionalFields[k] {
			pairs = append(pairs, kv{k, fmt.Sprintf("%v", v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })

	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "|")
}
