package output

import (
	"encoding/json"
	"io"

	"github.com/bouncerfox/cli/pkg/document"
)

const (
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifVersion = "2.1.0"
	toolName     = "BouncerFox"
	toolVersion  = "0.1.0"
	toolInfoURI  = "https://github.com/bouncerfox/cli"
)

// --- SARIF type hierarchy ---

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifReportingDescriptor struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifDriver struct {
	Name           string                     `json:"name"`
	Version        string                     `json:"version"`
	InformationURI string                     `json:"informationUri"`
	Rules          []sarifReportingDescriptor `json:"rules"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifOutput struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

// severityToSARIFLevel maps a FindingSeverity to a SARIF level string.
func severityToSARIFLevel(s document.FindingSeverity) string {
	switch s {
	case document.SeverityCritical, document.SeverityHigh:
		return "error"
	case document.SeverityWarn:
		return "warning"
	default:
		return "note"
	}
}

// FormatSARIF writes SARIF v2.1.0 output to w.
func FormatSARIF(findings []document.ScanFinding, w io.Writer) error {
	// Build deduplicated rules list (preserving first-seen order).
	seen := map[string]bool{}
	rules := []sarifReportingDescriptor{}
	for _, f := range findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			rules = append(rules, sarifReportingDescriptor{
				ID:               f.RuleID,
				ShortDescription: sarifMessage{Text: f.Message},
			})
		}
	}

	// Build results.
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		file, line := evidenceFileAndLine(f.Evidence)
		if line == 0 {
			line = 1 // SARIF requires startLine >= 1
		}

		var locs []sarifLocation
		if file != "" {
			locs = []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: file},
						Region:           sarifRegion{StartLine: line},
					},
				},
			}
		}

		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			Level:     severityToSARIFLevel(f.Severity),
			Message:   sarifMessage{Text: f.Message},
			Locations: locs,
		})
	}

	out := sarifOutput{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           toolName,
						Version:        toolVersion,
						InformationURI: toolInfoURI,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
