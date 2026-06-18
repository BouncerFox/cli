package platform

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readPhase1Fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "contracts", "phase1", name)
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
	for _, name := range []string{
		"upload-request-builtins.json",
		"upload-request-custom-rule.json",
		"upload-request-pr.json",
		"upload-request-local.json",
		"upload-request-privacy-mode.json",
	} {
		req := decodeStrict[UploadRequest](t, name)
		if req.Version != "1.0" {
			t.Fatalf("%s: expected version 1.0, got %q", name, req.Version)
		}
	}
}

func TestPhase1VerdictFixtures_DecodeStrictly(t *testing.T) {
	for _, name := range []string{
		"upload-verdict-pass.json",
		"upload-verdict-warn.json",
		"upload-verdict-fail.json",
		"upload-verdict-informational.json",
	} {
		resp := decodeStrict[VerdictResponse](t, name)
		if resp.Verdict == "" {
			t.Fatalf("%s: expected verdict", name)
		}
	}
}
