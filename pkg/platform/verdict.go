package platform

// VerdictResponse is the platform's response to a scan upload.
type VerdictResponse struct {
	ScanID       string          `json:"scan_id"`
	Verdict      string          `json:"verdict"` // "pass", "warn", "fail"
	Reasons      []VerdictReason `json:"reasons"`
	DashboardURL string          `json:"dashboard_url"`
}

// VerdictReason explains why a verdict was given.
type VerdictReason struct {
	Rule    string `json:"rule"`
	Policy  string `json:"policy"`
	Message string `json:"message"`
}

// ExitCode returns 0 for pass/warn, 1 for fail, 2 for any unrecognised verdict.
func (v *VerdictResponse) ExitCode() int {
	switch v.Verdict {
	case "pass", "warn":
		return 0
	case "fail":
		return 1
	default:
		return 2
	}
}
