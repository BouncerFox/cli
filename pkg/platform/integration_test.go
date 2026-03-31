package platform

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConnectedFlow_PassVerdict(t *testing.T) {
	// Mock platform: config pull returns config, upload returns pass verdict
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config/pull":
			w.Header().Set("ETag", `"v1"`)
			io.WriteString(w, "profile: recommended\n")
		case "/api/v1/scans/upload":
			// Verify the upload payload
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			json.Unmarshal(body, &req)

			if req["version"] != "1.0" {
				t.Errorf("expected version 1.0, got %v", req["version"])
			}
			if req["trigger"] != "ci" {
				t.Errorf("expected trigger ci, got %v", req["trigger"])
			}

			// Verify no snippet or evidence in findings
			raw := string(body)
			if strings.Contains(raw, `"snippet"`) {
				t.Error("upload must never contain snippet")
			}
			if strings.Contains(raw, `"evidence"`) {
				t.Error("upload must never contain evidence")
			}

			// Return pass verdict
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(VerdictResponse{
				ScanID:       "scan-1",
				Verdict:      "pass",
				ScanURL:      "https://app.bouncerfox.dev/scans/scan-1",
				FindingCount: 0,
				ProjectID:    "proj-1",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "bf_test_key")

	// Step 1: Pull config
	cfgResp, err := c.PullConfig(context.Background(), PullConfigRequest{Target: "github:test/repo"})
	if err != nil {
		t.Fatalf("PullConfig: %v", err)
	}
	if cfgResp.Body == "" {
		t.Error("expected non-empty config body")
	}

	// Step 2: Upload findings (simulating what main.go does)
	verdict, err := c.Upload(context.Background(), UploadRequest{
		Version:    "1.0",
		CLIVersion: "0.2.0",
		Target:     "github:test/repo",
		Trigger:    "ci",
		Timestamp:  "2026-03-27T00:00:00Z",
		Findings: []WireFinding{
			{RuleID: "QA_001", Severity: "warn", Message: "missing desc", Fingerprint: "fp1"},
		},
		IdempotencyKey: "test-key-1",
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if verdict.Verdict != "pass" {
		t.Errorf("expected pass, got %q", verdict.Verdict)
	}
	if verdict.ExitCode() != 0 {
		t.Errorf("pass should exit 0, got %d", verdict.ExitCode())
	}
}

func TestConnectedFlow_FailVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(VerdictResponse{
			ScanID:  "scan-2",
			Verdict: "fail",
			Reasons: []VerdictReason{
				{Rule: "SEC_001", Policy: "block_on_critical", Message: "Org policy blocks critical findings"},
			},
		})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "bf_test")
	verdict, err := c.Upload(context.Background(), UploadRequest{
		Version: "1.0",
		Trigger: "ci",
		Findings: []WireFinding{
			{RuleID: "SEC_001", Severity: "critical", Message: "hardcoded secret", Fingerprint: "fp2"},
		},
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if verdict.Verdict != "fail" {
		t.Errorf("expected fail, got %q", verdict.Verdict)
	}
	if verdict.ExitCode() != 1 {
		t.Errorf("fail should exit 1, got %d", verdict.ExitCode())
	}
	if len(verdict.Reasons) != 1 {
		t.Fatalf("expected 1 reason, got %d", len(verdict.Reasons))
	}
	if verdict.Reasons[0].Rule != "SEC_001" {
		t.Errorf("expected SEC_001, got %q", verdict.Reasons[0].Rule)
	}
}

func TestConnectedFlow_ConfigCacheIntegration(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		io.WriteString(w, "profile: recommended\n")
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "bf_test")
	cache := NewConfigCache(t.TempDir())
	key := "test-cache-key"

	// First pull: fresh
	resp1, _ := c.PullConfig(context.Background(), PullConfigRequest{})
	if resp1.NotModified {
		t.Error("first pull should not be 304")
	}
	cache.Store(key, resp1.Body, resp1.ETag)

	// Second pull with cached ETag: should get 304
	cached, ok := cache.Load(key)
	if !ok {
		t.Fatal("cache should have entry")
	}
	resp2, _ := c.PullConfig(context.Background(), PullConfigRequest{ETag: cached.ETag})
	if !resp2.NotModified {
		t.Error("second pull with ETag should get 304")
	}

	if callCount != 2 {
		t.Errorf("expected 2 server calls, got %d", callCount)
	}
}

func TestConnectedFlow_UploadPayloadNeverLeaksSecrets(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(VerdictResponse{Verdict: "pass"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "bf_test")
	_, err := c.Upload(context.Background(), UploadRequest{
		Version: "1.0",
		Trigger: "local",
		Findings: []WireFinding{
			{
				RuleID:      "SEC_001",
				Severity:    "critical",
				Message:     "secret pattern detected",
				File:        "CLAUDE.md",
				Line:        5,
				Fingerprint: "abc123",
				Remediation: "remove the secret",
			},
		},
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}

	raw := string(receivedBody)
	if strings.Contains(raw, `"snippet"`) {
		t.Error("payload must never contain snippet")
	}
	if strings.Contains(raw, `"evidence"`) {
		t.Error("payload must never contain evidence")
	}
	// The wire format should have top-level file/line, not nested in evidence
	var payload map[string]any
	json.Unmarshal(receivedBody, &payload)
	findings := payload["findings"].([]any)
	f := findings[0].(map[string]any)
	if f["file"] != "CLAUDE.md" {
		t.Errorf("expected file at top level, got %v", f["file"])
	}
}

func TestConnectedFlow_AnonymousOmitsIdentifyingInfo(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(VerdictResponse{Verdict: "pass"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "bf_test")
	// Simulate anonymous mode: omit target, commit, branch
	_, _ = c.Upload(context.Background(), UploadRequest{
		Version: "1.0",
		Trigger: "local",
		// target, target_label, commit_sha, branch all omitted (zero values)
		Findings: []WireFinding{
			{RuleID: "QA_001", Severity: "warn", Message: "test", Fingerprint: "fp"},
		},
	})

	var payload map[string]any
	json.Unmarshal(receivedBody, &payload)

	for _, key := range []string{"target", "target_label", "commit_sha", "branch"} {
		if v, ok := payload[key]; ok && v != "" {
			t.Errorf("anonymous mode: %s should be omitted, got %v", key, v)
		}
	}
}
