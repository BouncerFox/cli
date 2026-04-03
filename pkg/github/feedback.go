// Package github provides GitHub PR feedback: check runs and PR comments.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/bouncerfox/cli/pkg/document"
)

// validRepoComponent matches valid GitHub owner and repo name characters.
var validRepoComponent = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// baseURL is the GitHub API base URL. It can be overridden in tests.
var baseURL = "https://api.github.com"

// httpClient is used for all GitHub API requests (with a 30-second timeout).
var httpClient = &http.Client{Timeout: 30 * time.Second}

// commentMarker is the HTML comment embedded in PR comments so we can find and
// update our own comment on subsequent scans.
const commentMarker = "<!-- bouncerfox-scan -->"

// maxAnnotationsPerRequest is the GitHub API limit for annotations per check-run
// creation/update call.
const maxAnnotationsPerRequest = 50

// CheckRunOptions contains the inputs for PostCheckRun.
type CheckRunOptions struct {
	Token     string
	Owner     string
	Repo      string
	CommitSHA string
	Findings  []document.ScanFinding
	// Conclusion overrides the auto-derived conclusion when non-empty.
	// Accepted values: "success", "failure", "neutral".
	Conclusion string
}

// CommentOptions contains the inputs for PostPRComment.
type CommentOptions struct {
	Token    string
	Owner    string
	Repo     string
	PRNumber int
	Findings []document.ScanFinding
}

// DetectPRNumber returns the pull request number using the following priority:
//  1. flagValue if > 0
//  2. GITHUB_EVENT_PATH env var — reads the JSON file and extracts
//     .pull_request.number or .number
//  3. Returns 0 if not in a PR context (no error).
func DetectPRNumber(flagValue int) (int, error) {
	if flagValue > 0 {
		return flagValue, nil
	}

	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	if eventPath == "" {
		return 0, nil
	}

	f, err := os.Open(eventPath) //nolint:gosec // G304: reading GitHub event file from env
	if err != nil {
		return 0, fmt.Errorf("reading GITHUB_EVENT_PATH %q: %w", eventPath, err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, 1024*1024))
	if err != nil {
		return 0, fmt.Errorf("reading GITHUB_EVENT_PATH %q: %w", eventPath, err)
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return 0, fmt.Errorf("parsing GITHUB_EVENT_PATH %q: %w", eventPath, err)
	}

	// Try .pull_request.number first (push/PR event payloads).
	if pr, ok := payload["pull_request"].(map[string]any); ok {
		if n, ok := numericField(pr, "number"); ok {
			return n, nil
		}
	}

	// Fall back to top-level .number (issue_comment, etc.).
	if n, ok := numericField(payload, "number"); ok {
		return n, nil
	}

	return 0, nil
}

// DetectRepoInfo returns the owner and repo name from the GITHUB_REPOSITORY
// environment variable ("owner/repo") or from the git remote URL.
func DetectRepoInfo(ctx context.Context) (owner, repo string, err error) {
	if v := os.Getenv("GITHUB_REPOSITORY"); v != "" {
		parts := strings.SplitN(v, "/", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			if !validRepoComponent.MatchString(parts[0]) || !validRepoComponent.MatchString(parts[1]) {
				return "", "", fmt.Errorf("invalid GITHUB_REPOSITORY %q: owner and repo must contain only alphanumeric, dot, hyphen, or underscore characters", v)
			}
			return parts[0], parts[1], nil
		}
		return "", "", fmt.Errorf("malformed GITHUB_REPOSITORY %q: expected owner/repo", v)
	}

	// Fall back to parsing git remote.
	remote, err := gitRemoteURL(ctx)
	if err != nil {
		return "", "", fmt.Errorf("cannot detect repo info: GITHUB_REPOSITORY unset and git remote unavailable: %w", err)
	}

	o, r, parseErr := parseGitRemote(remote)
	if parseErr != nil {
		return "", "", fmt.Errorf("cannot parse git remote %q: %w", remote, parseErr)
	}
	return o, r, nil
}

// PostCheckRun creates a GitHub check run with annotations for all findings.
// If there are more than 50 findings, it paginates via update calls.
func PostCheckRun(ctx context.Context, opts CheckRunOptions) error {
	conclusion := opts.Conclusion
	if conclusion == "" {
		conclusion = DeriveConclusion(opts.Findings)
	}

	annotations := buildAnnotations(opts.Findings)

	// First batch (up to 50 annotations) goes in the create request.
	firstBatch := annotations
	rest := []annotation{}
	if len(annotations) > maxAnnotationsPerRequest {
		firstBatch = annotations[:maxAnnotationsPerRequest]
		rest = annotations[maxAnnotationsPerRequest:]
	}

	counts := countBySeverity(opts.Findings)
	summary := buildSummary(counts, len(opts.Findings))

	createBody := checkRunCreateRequest{
		Name:       "BouncerFox",
		HeadSHA:    opts.CommitSHA,
		Status:     "completed",
		Conclusion: conclusion,
		Output: checkRunOutput{
			Title:       "BouncerFox Scan Results",
			Summary:     summary,
			Annotations: firstBatch,
		},
	}

	respData, err := doRequest(ctx, http.MethodPost,
		fmt.Sprintf("%s/repos/%s/%s/check-runs", baseURL, url.PathEscape(opts.Owner), url.PathEscape(opts.Repo)),
		opts.Token, createBody)
	if err != nil {
		return fmt.Errorf("creating check run: %w", err)
	}

	// Extract the check run ID for potential follow-up PATCH calls.
	if len(rest) == 0 {
		return nil
	}

	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(respData, &created); err != nil || created.ID == 0 {
		return fmt.Errorf("parsing check run create response: %w", err)
	}

	// Send remaining annotations in batches via PATCH.
	for len(rest) > 0 {
		batch := rest
		if len(batch) > maxAnnotationsPerRequest {
			batch = rest[:maxAnnotationsPerRequest]
		}
		rest = rest[len(batch):]

		patchBody := checkRunUpdateRequest{
			Output: checkRunOutput{
				Title:       "BouncerFox Scan Results",
				Summary:     summary,
				Annotations: batch,
			},
		}
		_, err := doRequest(ctx, http.MethodPatch,
			fmt.Sprintf("%s/repos/%s/%s/check-runs/%d", baseURL, url.PathEscape(opts.Owner), url.PathEscape(opts.Repo), created.ID),
			opts.Token, patchBody)
		if err != nil {
			return fmt.Errorf("updating check run annotations: %w", err)
		}
	}

	return nil
}

// PostPRComment upserts a BouncerFox scan summary comment on the given PR.
// It looks for an existing comment containing commentMarker and either patches
// or creates it.
func PostPRComment(ctx context.Context, opts CommentOptions) error {
	existingID, err := findExistingComment(ctx, opts)
	if err != nil {
		return fmt.Errorf("finding existing comment: %w", err)
	}

	body := buildCommentBody(opts.Findings)

	if existingID > 0 {
		_, err = doRequest(ctx, http.MethodPatch,
			fmt.Sprintf("%s/repos/%s/%s/issues/comments/%d", baseURL, url.PathEscape(opts.Owner), url.PathEscape(opts.Repo), existingID),
			opts.Token, map[string]string{"body": body})
		if err != nil {
			return fmt.Errorf("updating PR comment: %w", err)
		}
		return nil
	}

	_, err = doRequest(ctx, http.MethodPost,
		fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", baseURL, url.PathEscape(opts.Owner), url.PathEscape(opts.Repo), opts.PRNumber),
		opts.Token, map[string]string{"body": body})
	if err != nil {
		return fmt.Errorf("posting PR comment: %w", err)
	}
	return nil
}

// --- internal helpers -------------------------------------------------------

// annotation is a single GitHub check run annotation.
type annotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"`
	Message         string `json:"message"`
	Title           string `json:"title,omitempty"`
}

type checkRunOutput struct {
	Title       string       `json:"title"`
	Summary     string       `json:"summary"`
	Annotations []annotation `json:"annotations,omitempty"`
}

type checkRunCreateRequest struct {
	Name       string         `json:"name"`
	HeadSHA    string         `json:"head_sha"`
	Status     string         `json:"status"`
	Conclusion string         `json:"conclusion"`
	Output     checkRunOutput `json:"output"`
}

type checkRunUpdateRequest struct {
	Output checkRunOutput `json:"output"`
}

// doRequest performs an authenticated JSON request and returns the response body.
func doRequest(ctx context.Context, method, url, token string, body any) ([]byte, error) {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshalling request body: %w", err)
		}
		buf = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, buf)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if readErr != nil {
		return nil, fmt.Errorf("reading response body: %w", readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GitHub API %s %s returned %d: %s", method, url, resp.StatusCode, string(truncateBytes(data, 500)))
	}
	return data, nil
}

// truncateBytes returns data trimmed to maxLen bytes.
func truncateBytes(data []byte, maxLen int) []byte {
	if len(data) <= maxLen {
		return data
	}
	return data[:maxLen]
}

// DeriveConclusion maps finding severities to a GitHub check conclusion.
func DeriveConclusion(findings []document.ScanFinding) string {
	if len(findings) == 0 {
		return "success"
	}
	for _, f := range findings {
		if f.Severity == document.SeverityCritical || f.Severity == document.SeverityHigh {
			return "failure"
		}
	}
	return "neutral"
}

// buildAnnotations converts findings to GitHub check run annotations.
func buildAnnotations(findings []document.ScanFinding) []annotation {
	anns := make([]annotation, 0, len(findings))
	for _, f := range findings {
		file, line := evidenceFileAndLine(f.Evidence)
		if file == "" {
			file = "."
		}
		if line <= 0 {
			line = 1
		}
		level := severityToAnnotationLevel(f.Severity)
		anns = append(anns, annotation{
			Path:            file,
			StartLine:       line,
			EndLine:         line,
			AnnotationLevel: level,
			Message:         f.Message,
			Title:           f.RuleID,
		})
	}
	return anns
}

// severityToAnnotationLevel maps FindingSeverity to GitHub annotation level.
func severityToAnnotationLevel(s document.FindingSeverity) string {
	switch s {
	case document.SeverityCritical, document.SeverityHigh:
		return "failure"
	case document.SeverityWarn:
		return "warning"
	default:
		return "notice"
	}
}

// countBySeverity returns a map of severity → count.
func countBySeverity(findings []document.ScanFinding) map[string]int {
	m := map[string]int{
		"critical": 0,
		"high":     0,
		"warn":     0,
		"info":     0,
	}
	for _, f := range findings {
		m[string(f.Severity)]++
	}
	return m
}

// buildSummary returns a markdown summary string.
func buildSummary(counts map[string]int, total int) string {
	return fmt.Sprintf(
		"**%d finding(s)** — %d critical, %d high, %d warn, %d info",
		total,
		counts["critical"],
		counts["high"],
		counts["warn"],
		counts["info"],
	)
}

// buildCommentBody renders the markdown comment body.
func buildCommentBody(findings []document.ScanFinding) string {
	var sb strings.Builder
	sb.WriteString(commentMarker + "\n")
	sb.WriteString("## BouncerFox Scan Results\n\n")

	counts := countBySeverity(findings)
	total := len(findings)
	sb.WriteString(buildSummary(counts, total))
	sb.WriteString("\n\n")

	if total == 0 {
		sb.WriteString("No findings. All checks passed.\n")
		return sb.String()
	}

	sb.WriteString("| Severity | Rule | File | Line | Message |\n")
	sb.WriteString("|----------|------|------|------|---------|\n")

	for _, f := range findings {
		file, line := evidenceFileAndLine(f.Evidence)
		lineStr := ""
		if line > 0 {
			lineStr = fmt.Sprintf("%d", line)
		}
		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s |\n",
			string(f.Severity),
			escapeMarkdown(f.RuleID),
			escapeMarkdown(file),
			lineStr,
			escapeMarkdown(f.Message),
		)
	}

	return sb.String()
}

// escapeMarkdown escapes characters that could be used for markdown injection
// in PR comments (pipes, links, and HTML tags).
func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;") // must be first to avoid double-escaping
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "[", "\\[")
	s = strings.ReplaceAll(s, "]", "\\]")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// findExistingComment searches for a PR comment containing commentMarker and
// returns its ID, or 0 if not found.
func findExistingComment(ctx context.Context, opts CommentOptions) (int64, error) {
	reqURL := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments?per_page=100",
		baseURL, url.PathEscape(opts.Owner), url.PathEscape(opts.Repo), opts.PRNumber)

	data, err := doRequest(ctx, http.MethodGet, reqURL, opts.Token, nil)
	if err != nil {
		return 0, err
	}

	var comments []struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal(data, &comments); err != nil {
		return 0, fmt.Errorf("parsing comments response: %w", err)
	}

	for _, c := range comments {
		if strings.Contains(c.Body, commentMarker) {
			return c.ID, nil
		}
	}

	return 0, nil
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

// numericField extracts a numeric field from a JSON-decoded map[string]any,
// tolerating both float64 (JSON numbers) and int.
func numericField(m map[string]any, key string) (int, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}

// parseGitRemote extracts owner and repo from a git remote URL.
// Supports both HTTPS (https://github.com/owner/repo.git) and
// SSH (git@github.com:owner/repo.git) formats.
func parseGitRemote(remote string) (owner, repo string, err error) {
	// Normalise: strip trailing .git
	remote = strings.TrimSuffix(remote, ".git")
	remote = strings.TrimSpace(remote)

	// SSH: git@github.com:owner/repo
	if idx := strings.Index(remote, ":"); idx != -1 && !strings.HasPrefix(remote, "http") {
		path := remote[idx+1:]
		parts := strings.SplitN(path, "/", 2)
		if len(parts) == 2 {
			return parts[0], parts[1], nil
		}
	}

	// HTTPS: https://github.com/owner/repo
	if strings.HasPrefix(remote, "http") {
		// Find everything after the host.
		// Strip scheme.
		after := strings.SplitN(remote, "//", 2)
		if len(after) == 2 {
			// Strip host.
			parts := strings.SplitN(after[1], "/", 3)
			if len(parts) == 3 {
				return parts[1], parts[2], nil
			}
		}
	}

	return "", "", fmt.Errorf("unrecognised remote format: %q", remote)
}

// gitRemoteURL returns the URL of the "origin" remote by running git.
func gitRemoteURL(ctx context.Context) (string, error) {
	return runGitRemote(ctx)
}
