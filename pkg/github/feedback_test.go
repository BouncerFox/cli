package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/bouncerfox/cli/pkg/document"
)

// ---- DetectPRNumber --------------------------------------------------------

func TestDetectPRNumber_FlagTakesPriority(t *testing.T) {
	n, err := DetectPRNumber(42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 42 {
		t.Errorf("got %d, want 42", n)
	}
}

func TestDetectPRNumber_EnvPullRequest(t *testing.T) {
	payload := map[string]any{
		"pull_request": map[string]any{
			"number": float64(7),
		},
	}
	f := writeTempJSON(t, payload)
	t.Setenv("GITHUB_EVENT_PATH", f)

	n, err := DetectPRNumber(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 7 {
		t.Errorf("got %d, want 7", n)
	}
}

func TestDetectPRNumber_EnvTopLevelNumber(t *testing.T) {
	payload := map[string]any{
		"number": float64(99),
	}
	f := writeTempJSON(t, payload)
	t.Setenv("GITHUB_EVENT_PATH", f)

	n, err := DetectPRNumber(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 99 {
		t.Errorf("got %d, want 99", n)
	}
}

func TestDetectPRNumber_NoPRContext(t *testing.T) {
	t.Setenv("GITHUB_EVENT_PATH", "")
	n, err := DetectPRNumber(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("got %d, want 0", n)
	}
}

func TestDetectPRNumber_MissingFile(t *testing.T) {
	t.Setenv("GITHUB_EVENT_PATH", "/tmp/nonexistent-bouncerfox-event.json")
	_, err := DetectPRNumber(0)
	if err == nil {
		t.Fatal("expected error for missing event file, got nil")
	}
}

// ---- DetectRepoInfo --------------------------------------------------------

func TestDetectRepoInfo_EnvVar(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "acme/my-repo")
	owner, repo, err := DetectRepoInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "acme" || repo != "my-repo" {
		t.Errorf("got owner=%q repo=%q, want acme/my-repo", owner, repo)
	}
}

func TestDetectRepoInfo_MalformedEnvVar(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "no-slash")
	_, _, err := DetectRepoInfo()
	if err == nil {
		t.Fatal("expected error for malformed GITHUB_REPOSITORY, got nil")
	}
}

// ---- parseGitRemote --------------------------------------------------------

func TestParseGitRemote_HTTPS(t *testing.T) {
	cases := []struct{ remote, owner, repo string }{
		{"https://github.com/acme/cli.git", "acme", "cli"},
		{"https://github.com/acme/cli", "acme", "cli"},
	}
	for _, c := range cases {
		o, r, err := parseGitRemote(c.remote)
		if err != nil {
			t.Errorf("parseGitRemote(%q): unexpected error %v", c.remote, err)
			continue
		}
		if o != c.owner || r != c.repo {
			t.Errorf("parseGitRemote(%q) = %q/%q, want %q/%q", c.remote, o, r, c.owner, c.repo)
		}
	}
}

func TestParseGitRemote_SSH(t *testing.T) {
	cases := []struct{ remote, owner, repo string }{
		{"git@github.com:acme/cli.git", "acme", "cli"},
		{"git@github.com:acme/cli", "acme", "cli"},
	}
	for _, c := range cases {
		o, r, err := parseGitRemote(c.remote)
		if err != nil {
			t.Errorf("parseGitRemote(%q): unexpected error %v", c.remote, err)
			continue
		}
		if o != c.owner || r != c.repo {
			t.Errorf("parseGitRemote(%q) = %q/%q, want %q/%q", c.remote, o, r, c.owner, c.repo)
		}
	}
}

// ---- helper functions ------------------------------------------------------

func TestDeriveConclusion(t *testing.T) {
	cases := []struct {
		findings   []document.ScanFinding
		conclusion string
	}{
		{nil, "success"},
		{[]document.ScanFinding{}, "success"},
		{
			[]document.ScanFinding{{Severity: document.SeverityWarn}},
			"neutral",
		},
		{
			[]document.ScanFinding{{Severity: document.SeverityInfo}},
			"neutral",
		},
		{
			[]document.ScanFinding{{Severity: document.SeverityHigh}},
			"failure",
		},
		{
			[]document.ScanFinding{{Severity: document.SeverityCritical}},
			"failure",
		},
	}
	for _, c := range cases {
		got := DeriveConclusion(c.findings)
		if got != c.conclusion {
			t.Errorf("DeriveConclusion(%v findings) = %q, want %q", len(c.findings), got, c.conclusion)
		}
	}
}

func TestSeverityToAnnotationLevel(t *testing.T) {
	cases := []struct {
		sev   document.FindingSeverity
		level string
	}{
		{document.SeverityCritical, "failure"},
		{document.SeverityHigh, "failure"},
		{document.SeverityWarn, "warning"},
		{document.SeverityInfo, "notice"},
	}
	for _, c := range cases {
		got := severityToAnnotationLevel(c.sev)
		if got != c.level {
			t.Errorf("severityToAnnotationLevel(%q) = %q, want %q", c.sev, got, c.level)
		}
	}
}

func TestBuildCommentBody_NoFindings(t *testing.T) {
	body := buildCommentBody(nil)
	if !strings.Contains(body, commentMarker) {
		t.Error("expected comment marker in body")
	}
	if !strings.Contains(body, "No findings") {
		t.Error("expected 'No findings' message")
	}
}

func TestBuildCommentBody_WithFindings(t *testing.T) {
	findings := []document.ScanFinding{
		{
			RuleID:   "SEC_001",
			Severity: document.SeverityCritical,
			Message:  "hardcoded secret",
			Evidence: map[string]any{"file": "foo.md", "line": 3},
		},
		{
			RuleID:   "QA_001",
			Severity: document.SeverityWarn,
			Message:  "missing description",
			Evidence: map[string]any{"file": "bar.md", "line": 10},
		},
	}
	body := buildCommentBody(findings)
	if !strings.Contains(body, commentMarker) {
		t.Error("expected comment marker")
	}
	if !strings.Contains(body, "SEC_001") {
		t.Error("expected rule ID in body")
	}
	if !strings.Contains(body, "foo.md") {
		t.Error("expected file name in body")
	}
	if !strings.Contains(body, "| Severity |") {
		t.Error("expected table header in body")
	}
}

func TestBuildAnnotations(t *testing.T) {
	findings := []document.ScanFinding{
		{
			RuleID:   "SEC_001",
			Severity: document.SeverityCritical,
			Message:  "secret found",
			Evidence: map[string]any{"file": "agent.md", "line": 5},
		},
		{
			RuleID:   "QA_002",
			Severity: document.SeverityInfo,
			Message:  "no remediation",
			Evidence: nil,
		},
	}
	anns := buildAnnotations(findings)
	if len(anns) != 2 {
		t.Fatalf("expected 2 annotations, got %d", len(anns))
	}
	if anns[0].Path != "agent.md" {
		t.Errorf("expected path=agent.md, got %q", anns[0].Path)
	}
	if anns[0].StartLine != 5 || anns[0].EndLine != 5 {
		t.Errorf("expected line 5, got start=%d end=%d", anns[0].StartLine, anns[0].EndLine)
	}
	if anns[0].AnnotationLevel != "failure" {
		t.Errorf("expected failure level, got %q", anns[0].AnnotationLevel)
	}
	// Finding with nil evidence should fall back to path="." line=1
	if anns[1].Path != "." {
		t.Errorf("expected fallback path='.', got %q", anns[1].Path)
	}
	if anns[1].StartLine != 1 {
		t.Errorf("expected fallback line=1, got %d", anns[1].StartLine)
	}
}

// ---- PostCheckRun (mock HTTP) ----------------------------------------------

func TestPostCheckRun_Success(t *testing.T) {
	var mu sync.Mutex
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/check-runs"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": float64(123)})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	orig := baseURL
	baseURL = srv.URL
	defer func() { baseURL = orig }()

	findings := []document.ScanFinding{
		{RuleID: "SEC_001", Severity: document.SeverityHigh, Message: "test", Evidence: map[string]any{"file": "f.md", "line": 1}},
	}
	err := PostCheckRun(context.Background(), CheckRunOptions{
		Token:     "tok",
		Owner:     "acme",
		Repo:      "cli",
		CommitSHA: "abc123",
		Findings:  findings,
	})
	if err != nil {
		t.Fatalf("PostCheckRun: %v", err)
	}
	if len(calls) != 1 {
		t.Errorf("expected 1 API call, got %d: %v", len(calls), calls)
	}
}

func TestPostCheckRun_PaginatesAnnotations(t *testing.T) {
	// Generate 55 findings — should result in 1 POST + 1 PATCH.
	findings := make([]document.ScanFinding, 55)
	for i := range findings {
		findings[i] = document.ScanFinding{
			RuleID:   "SEC_001",
			Severity: document.SeverityWarn,
			Message:  "finding " + strconv.Itoa(i),
			Evidence: map[string]any{"file": "f.md", "line": i + 1},
		}
	}

	var mu sync.Mutex
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": float64(42)})
		} else {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": float64(42)})
		}
	}))
	defer srv.Close()

	orig := baseURL
	baseURL = srv.URL
	defer func() { baseURL = orig }()

	err := PostCheckRun(context.Background(), CheckRunOptions{
		Token:     "tok",
		Owner:     "acme",
		Repo:      "cli",
		CommitSHA: "abc123",
		Findings:  findings,
	})
	if err != nil {
		t.Fatalf("PostCheckRun: %v", err)
	}

	mu.Lock()
	n := len(calls)
	mu.Unlock()

	// 1 POST to create + 1 PATCH for the remaining 5 annotations.
	if n != 2 {
		t.Errorf("expected 2 API calls (POST + PATCH), got %d: %v", n, calls)
	}
}

func TestPostCheckRun_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()

	orig := baseURL
	baseURL = srv.URL
	defer func() { baseURL = orig }()

	err := PostCheckRun(context.Background(), CheckRunOptions{
		Token: "bad", Owner: "acme", Repo: "cli", CommitSHA: "sha",
	})
	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
}

// ---- PostPRComment (mock HTTP) ---------------------------------------------

func TestPostPRComment_NewComment(t *testing.T) {
	var mu sync.Mutex
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "comments"):
			// Return empty list — no existing comment.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[]"))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "comments"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": float64(1)})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	orig := baseURL
	baseURL = srv.URL
	defer func() { baseURL = orig }()

	err := PostPRComment(context.Background(), CommentOptions{
		Token:    "tok",
		Owner:    "acme",
		Repo:     "cli",
		PRNumber: 5,
		Findings: nil,
	})
	if err != nil {
		t.Fatalf("PostPRComment: %v", err)
	}

	mu.Lock()
	n := len(calls)
	mu.Unlock()

	// 1 GET to list comments + 1 POST to create.
	if n != 2 {
		t.Errorf("expected 2 calls, got %d: %v", n, calls)
	}
}

func TestPostPRComment_UpdatesExisting(t *testing.T) {
	var mu sync.Mutex
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "comments"):
			// Return one existing comment containing the marker.
			existing := []map[string]any{
				{"id": float64(99), "body": commentMarker + "\n## BouncerFox old results"},
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(existing)
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/99"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": float64(99)})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	orig := baseURL
	baseURL = srv.URL
	defer func() { baseURL = orig }()

	findings := []document.ScanFinding{
		{RuleID: "SEC_001", Severity: document.SeverityCritical, Message: "secret", Evidence: map[string]any{"file": "a.md", "line": 1}},
	}
	err := PostPRComment(context.Background(), CommentOptions{
		Token: "tok", Owner: "acme", Repo: "cli", PRNumber: 5, Findings: findings,
	})
	if err != nil {
		t.Fatalf("PostPRComment: %v", err)
	}

	mu.Lock()
	callsCopy := append([]string{}, calls...)
	mu.Unlock()

	// 1 GET + 1 PATCH.
	if len(callsCopy) != 2 {
		t.Errorf("expected 2 calls, got %d: %v", len(callsCopy), callsCopy)
	}
	found := false
	for _, c := range callsCopy {
		if strings.HasPrefix(c, "PATCH") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PATCH call, got: %v", callsCopy)
	}
}

func TestPostPRComment_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Forbidden"}`))
	}))
	defer srv.Close()

	orig := baseURL
	baseURL = srv.URL
	defer func() { baseURL = orig }()

	err := PostPRComment(context.Background(), CommentOptions{
		Token: "bad", Owner: "acme", Repo: "cli", PRNumber: 1,
	})
	if err == nil {
		t.Fatal("expected error for 403 response, got nil")
	}
}

// ---- utilities -------------------------------------------------------------

func writeTempJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	f := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return f
}
