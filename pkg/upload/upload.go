// Package upload provides payload builder utilities for the BouncerFox platform.
package upload

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/platform"
)

// Version is the payload schema version.
const Version = "1.0"

const maxMessageLen = 500

// IdempotencyKey generates a deterministic key for upload deduplication.
// For git scans: sha256(target + commitSHA + configHash + sorted fingerprints).
// For non-git scans: caller should pass a UUID nonce as commitSHA.
func IdempotencyKey(target, commitSHA, configHash string, fingerprints []string) string {
	sorted := make([]string, len(fingerprints))
	copy(sorted, fingerprints)
	sort.Strings(sorted)

	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n", target, commitSHA, configHash)
	for _, fp := range sorted {
		fmt.Fprintf(h, "%s\n", fp)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// BuildWireFindings converts ScanFindings to the platform wire format,
// applying path transformations according to stripPaths and anonymous flags.
func BuildWireFindings(findings []document.ScanFinding, stripPaths, anonymous bool) []platform.WireFinding {
	out := make([]platform.WireFinding, 0, len(findings))
	for _, f := range findings {
		msg := f.Message
		if len(msg) > maxMessageLen {
			msg = msg[:maxMessageLen]
		}

		wf := platform.WireFinding{
			RuleID:      f.RuleID,
			Severity:    string(f.Severity),
			Message:     msg,
			Fingerprint: evidenceString(f.Evidence, "fingerprint"),
			Remediation: f.Remediation,
		}

		if !anonymous {
			file := evidenceString(f.Evidence, "file")
			if stripPaths && file != "" {
				file = filepath.Base(file)
			}
			wf.File = file
			wf.Line = evidenceInt(f.Evidence, "line")
		}

		out = append(out, wf)
	}
	return out
}

func evidenceString(ev map[string]any, key string) string {
	if ev == nil {
		return ""
	}
	if v, ok := ev[key].(string); ok {
		return v
	}
	return ""
}

func evidenceInt(ev map[string]any, key string) int {
	if ev == nil {
		return 0
	}
	switch v := ev[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	}
	return 0
}
