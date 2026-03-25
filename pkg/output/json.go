package output

import (
	"encoding/json"
	"io"

	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/fingerprint"
)

// jsonEvidence is the structured evidence object emitted in JSON output.
type jsonEvidence struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet,omitempty"`
}

// jsonFinding is the per-finding object emitted in JSON output.
type jsonFinding struct {
	RuleID      string       `json:"rule_id"`
	Severity    string       `json:"severity"`
	Message     string       `json:"message"`
	Evidence    jsonEvidence `json:"evidence"`
	Remediation string       `json:"remediation"`
	Fingerprint string       `json:"fingerprint"`
}

// jsonSummary holds aggregate counts.
type jsonSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
}

// jsonOutput is the top-level JSON document.
type jsonOutput struct {
	Version  string        `json:"version"`
	Findings []jsonFinding `json:"findings"`
	Summary  jsonSummary   `json:"summary"`
}

// FormatJSON writes spec-compliant JSON to w.
func FormatJSON(findings []document.ScanFinding, w io.Writer) error {
	jf := make([]jsonFinding, 0, len(findings))
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"warn":     0,
		"info":     0,
	}

	for _, f := range findings {
		counts[string(f.Severity)]++
		file, line := evidenceFileAndLine(f.Evidence)
		snippet := ""
		if f.Evidence != nil {
			if v, ok := f.Evidence["snippet"]; ok {
				snippet, _ = v.(string)
			}
		}
		jf = append(jf, jsonFinding{
			RuleID:   f.RuleID,
			Severity: string(f.Severity),
			Message:  f.Message,
			Evidence: jsonEvidence{
				File:    file,
				Line:    line,
				Snippet: snippet,
			},
			Remediation: f.Remediation,
			Fingerprint: fingerprint.ComputeFingerprint(f),
		})
	}

	out := jsonOutput{
		Version:  "1.0",
		Findings: jf,
		Summary: jsonSummary{
			Total:      len(findings),
			BySeverity: counts,
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
