package platform

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func phase1FixtureDir() string {
	return filepath.Join("..", "..", "testdata", "contracts", "phase1")
}

func readPhase1Fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(phase1FixtureDir(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func decodeStrict[T any](t *testing.T, name string) T {
	t.Helper()
	var out T
	dec := json.NewDecoder(bytes.NewReader(readPhase1Fixture(t, name)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return out
}

func TestPhase1SkillFixture_AcceptsContentHash(t *testing.T) {
	got := decodeStrict[SkillMetadata](t, "skill-metadata-with-content-hash.json")
	if got.ContentHash == "" {
		t.Fatal("expected content_hash to decode into SkillMetadata")
	}
}

func TestPhase1UploadRequestFixtures_DecodeStrictly(t *testing.T) {
	t.Run("builtins", func(t *testing.T) {
		req := decodeStrict[UploadRequest](t, "upload-request-builtins.json")
		if req.Version != "1.0" {
			t.Fatalf("expected version 1.0, got %q", req.Version)
		}
		if req.CLIChecksum == "" {
			t.Fatal("expected cli_checksum in builtins fixture")
		}
		if len(req.Findings) != 1 || req.Findings[0].RuleID != "SEC_001" {
			t.Fatalf("expected one SEC_001 finding, got %+v", req.Findings)
		}
	})

	t.Run("pr", func(t *testing.T) {
		req := decodeStrict[UploadRequest](t, "upload-request-pr.json")
		if req.PRNumber != 42 {
			t.Fatalf("expected pr_number 42, got %d", req.PRNumber)
		}
		if len(req.Skills) != 1 {
			t.Fatalf("expected 1 skill, got %d", len(req.Skills))
		}
		if req.Skills[0].ContentHash == "" {
			t.Fatal("expected non-empty content_hash in PR skill metadata")
		}
	})

	t.Run("privacy_mode", func(t *testing.T) {
		req := decodeStrict[UploadRequest](t, "upload-request-privacy-mode.json")
		if len(req.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(req.Findings))
		}
		if req.Findings[0].File != "" {
			t.Fatalf("expected decoded file field to be empty, got %q", req.Findings[0].File)
		}

		var raw map[string]any
		if err := json.Unmarshal(readPhase1Fixture(t, "upload-request-privacy-mode.json"), &raw); err != nil {
			t.Fatalf("decode raw privacy-mode fixture: %v", err)
		}
		findings, ok := raw["findings"].([]any)
		if !ok || len(findings) != 1 {
			t.Fatalf("expected 1 raw finding, got %#v", raw["findings"])
		}
		finding, ok := findings[0].(map[string]any)
		if !ok {
			t.Fatalf("expected raw finding object, got %#v", findings[0])
		}
		if _, ok := finding["file"]; ok {
			t.Fatal("expected privacy-mode raw JSON finding to omit file field")
		}
	})
}

func TestPhase1ConfigPullRequestFixture_DecodeStrictly(t *testing.T) {
	type pullRequest struct {
		Target string `json:"target"`
		ETag   string `json:"etag"`
	}

	req := decodeStrict[pullRequest](t, "config-pull-request.json")
	if req.Target != "github:acme/repo" {
		t.Fatalf("expected github target, got %q", req.Target)
	}
	if req.ETag != "\"cfg-v1\"" {
		t.Fatalf("expected canonical etag, got %q", req.ETag)
	}
}

func TestPhase1VerdictFixtures_DecodeStrictly(t *testing.T) {
	tests := []struct {
		name         string
		verdict      string
		findingCount int
		reasons      int
	}{
		{name: "upload-verdict-pass.json", verdict: "pass", findingCount: 0, reasons: 0},
		{name: "upload-verdict-warn.json", verdict: "warn", findingCount: 1, reasons: 1},
		{name: "upload-verdict-fail.json", verdict: "fail", findingCount: 1, reasons: 1},
		{name: "upload-verdict-informational.json", verdict: "informational", findingCount: 0, reasons: 0},
	}

	for _, tt := range tests {
		resp := decodeStrict[VerdictResponse](t, tt.name)
		if resp.Verdict != tt.verdict {
			t.Fatalf("%s: expected verdict %q, got %q", tt.name, tt.verdict, resp.Verdict)
		}
		if resp.FindingCount != tt.findingCount {
			t.Fatalf("%s: expected finding_count %d, got %d", tt.name, tt.findingCount, resp.FindingCount)
		}
		if len(resp.Reasons) != tt.reasons {
			t.Fatalf("%s: expected %d reasons, got %d", tt.name, tt.reasons, len(resp.Reasons))
		}
		if tt.reasons > 0 && resp.Reasons[0].Message == "" {
			t.Fatalf("%s: expected first reason message", tt.name)
		}
		if resp.ScanID == "" || resp.ProjectID == "" || resp.ScanURL == "" {
			t.Fatalf("%s: expected scan metadata fields to be populated: %+v", tt.name, resp)
		}
	}
}

func TestPhase1ErrorFixtures_HaveStableShape(t *testing.T) {
	for _, name := range []string{
		"error-401.json",
		"error-402.json",
		"error-403.json",
		"error-409.json",
		"error-422.json",
	} {
		var payload map[string]string
		dec := json.NewDecoder(bytes.NewReader(readPhase1Fixture(t, name)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&payload); err != nil {
			t.Fatalf("%s: decode error fixture: %v", name, err)
		}
		if len(payload) != 2 {
			t.Fatalf("%s: expected exactly 2 keys, got %v", name, payload)
		}
		if payload["error"] == "" || payload["message"] == "" {
			t.Fatalf("%s: expected non-empty error and message, got %v", name, payload)
		}
	}
}

func TestPhase1Manifest_MatchesFixtureBytes(t *testing.T) {
	manifest := decodeStrict[struct {
		Version  int               `json:"version"`
		Fixtures map[string]string `json:"fixtures"`
	}](t, "manifest.json")

	if manifest.Version != 1 {
		t.Fatalf("expected manifest version 1, got %d", manifest.Version)
	}

	entries, err := os.ReadDir(phase1FixtureDir())
	if err != nil {
		t.Fatalf("read fixture dir: %v", err)
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" || entry.Name() == "manifest.json" {
			continue
		}
		names = append(names, entry.Name())
		data := readPhase1Fixture(t, entry.Name())
		sum := sha256.Sum256(data)
		want := fmt.Sprintf("sha256:%x", sum)
		if got := manifest.Fixtures[entry.Name()]; got != want {
			t.Fatalf("%s: manifest digest = %q, want %q", entry.Name(), got, want)
		}
	}

	slices.Sort(names)
	var manifestNames []string
	for name := range manifest.Fixtures {
		manifestNames = append(manifestNames, name)
	}
	slices.Sort(manifestNames)
	if !slices.Equal(manifestNames, names) {
		t.Fatalf("manifest fixture keys = %v, want %v", manifestNames, names)
	}
}
