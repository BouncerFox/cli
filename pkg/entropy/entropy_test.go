package entropy

import (
	"math"
	"strings"
	"testing"
)

// ── ShannonEntropy ────────────────────────────────────────────────────────────

func TestShannonEntropy_Empty(t *testing.T) {
	if got := ShannonEntropy(""); got != 0.0 {
		t.Errorf("ShannonEntropy(\"\") = %v, want 0.0", got)
	}
}

func TestShannonEntropy_SingleChar(t *testing.T) {
	if got := ShannonEntropy("aaaa"); got != 0.0 {
		t.Errorf("ShannonEntropy(\"aaaa\") = %v, want 0.0 (single unique char)", got)
	}
}

func TestShannonEntropy_TwoChars(t *testing.T) {
	// "abababab" — equal distribution of 2 chars → entropy = 1.0
	got := ShannonEntropy("abababab")
	if math.Abs(got-1.0) > 0.001 {
		t.Errorf("ShannonEntropy(\"abababab\") = %v, want ~1.0", got)
	}
}

func TestShannonEntropy_HighEntropy(t *testing.T) {
	// A random-looking base64 string should have high entropy
	s := "aB3xK9mZqR2nP7wL"
	got := ShannonEntropy(s)
	if got < 3.5 {
		t.Errorf("ShannonEntropy(%q) = %v, expected >= 3.5 for high-entropy string", s, got)
	}
}

func TestShannonEntropy_Uniform(t *testing.T) {
	// 4 equally distributed characters: max entropy for 4 symbols is 2.0
	got := ShannonEntropy("abcdabcdabcdabcd")
	if math.Abs(got-2.0) > 0.001 {
		t.Errorf("ShannonEntropy = %v, want ~2.0", got)
	}
}

// ── ClassifyCharset ───────────────────────────────────────────────────────────

func TestClassifyCharset_Hex(t *testing.T) {
	cases := []string{"deadbeef", "DEADBEEF", "0123456789abcdef", "ABCDEF"}
	for _, s := range cases {
		if got := ClassifyCharset(s); got != "hex" {
			t.Errorf("ClassifyCharset(%q) = %q, want \"hex\"", s, got)
		}
	}
}

func TestClassifyCharset_Base64(t *testing.T) {
	cases := []string{"aGVsbG8=", "dGVzdA==", "aGVsbG8", "abc123+/"}
	for _, s := range cases {
		if got := ClassifyCharset(s); got != "base64" {
			t.Errorf("ClassifyCharset(%q) = %q, want \"base64\"", s, got)
		}
	}
}

func TestClassifyCharset_Mixed(t *testing.T) {
	cases := []string{"hello world!", "secret!value", "abc_DEF-123!"}
	for _, s := range cases {
		if got := ClassifyCharset(s); got != "mixed" {
			t.Errorf("ClassifyCharset(%q) = %q, want \"mixed\"", s, got)
		}
	}
}

func TestClassifyCharset_HexBeforeBase64(t *testing.T) {
	// Pure hex is a subset of base64, so hex check must come first
	if got := ClassifyCharset("abcdef1234567890"); got != "hex" {
		t.Errorf("ClassifyCharset(\"abcdef1234567890\") = %q, want \"hex\"", got)
	}
}

// ── DetectContext ─────────────────────────────────────────────────────────────

func TestDetectContext_Credential(t *testing.T) {
	cases := []string{
		"api_key=somevalue",
		"API_KEY: somevalue",
		"secret: abc123",
		"token=xyz",
		"password=hunter2",
		"passwd=abc",
		"credential=abc",
		"auth=bearer",
	}
	for _, line := range cases {
		if got := DetectContext(line); got != "credential" {
			t.Errorf("DetectContext(%q) = %q, want \"credential\"", line, got)
		}
	}
}

func TestDetectContext_Freetext(t *testing.T) {
	cases := []string{
		"this is just some text",
		"no sensitive info here",
		"the hash value is abc123",
	}
	for _, line := range cases {
		if got := DetectContext(line); got != "freetext" {
			t.Errorf("DetectContext(%q) = %q, want \"freetext\"", line, got)
		}
	}
}

func TestDetectContext_CaseInsensitive(t *testing.T) {
	if got := DetectContext("API-KEY=abc"); got != "credential" {
		t.Errorf("DetectContext(\"API-KEY=abc\") = %q, want \"credential\"", got)
	}
}

// ── ExtractCandidates ─────────────────────────────────────────────────────────

func TestExtractCandidates_BasicToken(t *testing.T) {
	// A long enough token should be extracted
	candidates := ExtractCandidates("key="+randomToken32, 16)
	if len(candidates) == 0 {
		t.Error("expected at least one candidate")
	}
}

func TestExtractCandidates_TooShort(t *testing.T) {
	candidates := ExtractCandidates("short=abc", 16)
	if len(candidates) != 0 {
		t.Errorf("got %d candidates, want 0 (token too short)", len(candidates))
	}
}

func TestExtractCandidates_FilterUUID(t *testing.T) {
	uuid := "123e4567-e89b-12d3-a456-426614174000"
	candidates := ExtractCandidates("id="+uuid, 16)
	// The UUID with dashes won't match the token regex as one token,
	// but the hex parts will. Let's check that UUIDs are filtered.
	for _, c := range candidates {
		if c == uuid {
			t.Errorf("UUID should be filtered, got %q", c)
		}
	}
}

func TestExtractCandidates_FilterGitSHA(t *testing.T) {
	sha := "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
	candidates := ExtractCandidates("commit="+sha, 16)
	for _, c := range candidates {
		if c == sha {
			t.Errorf("git SHA should be filtered, got %q", c)
		}
	}
}

func TestExtractCandidates_FilterSHA256(t *testing.T) {
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	candidates := ExtractCandidates("hash="+sha256, 16)
	for _, c := range candidates {
		if c == sha256 {
			t.Errorf("SHA-256 should be filtered, got %q", c)
		}
	}
}

func TestExtractCandidates_FilterURL(t *testing.T) {
	// Tokens containing "://" should be excluded
	candidates := ExtractCandidates("https://example.com/path", 16)
	for _, c := range candidates {
		if c == "https://example.com/path" {
			t.Errorf("URL token should be filtered: %q", c)
		}
	}
}

func TestExtractCandidates_FilterFilePath(t *testing.T) {
	// Tokens containing "/" should be excluded
	candidates := ExtractCandidates("path=/usr/local/bin/tool", 16)
	for _, c := range candidates {
		if len(c) >= 16 && strings.Contains(c, "/") {
			t.Errorf("file path token should be filtered: %q", c)
		}
	}
}

func TestExtractCandidates_WindowsPathPrecededByBackslash(t *testing.T) {
	// Token preceded by backslash should be excluded
	candidates := ExtractCandidates(`dir=C:\Users\ABCDEFGHIJKLMNOPQRSTUVWXYZ`, 16)
	for _, c := range candidates {
		if c == "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
			t.Errorf("token preceded by backslash should be filtered: %q", c)
		}
	}
}

func TestExtractCandidates_MultipleTokens(t *testing.T) {
	// Two long tokens on the same line
	line := "key1=" + randomToken32 + " key2=" + randomToken32
	candidates := ExtractCandidates(line, 16)
	if len(candidates) < 2 {
		t.Errorf("expected >= 2 candidates, got %d", len(candidates))
	}
}

// ── Edge case tests ─────────────────────────────────────────────────────────

func TestShannonEntropy_AllSameChar(t *testing.T) {
	got := ShannonEntropy("aaaaaaaaaa")
	if got != 0.0 {
		t.Errorf("all same chars should have 0 entropy, got %f", got)
	}
}

func TestShannonEntropy_MaxEntropy(t *testing.T) {
	// ShannonEntropy operates on runes, not raw bytes. When 256 raw bytes
	// (0x00-0xFF) are converted to a Go string, many high bytes form
	// invalid UTF-8 sequences that collapse into fewer unique runes,
	// yielding ~4.5 bits rather than the theoretical 8.0.
	var input []byte
	for i := 0; i < 256; i++ {
		input = append(input, byte(i))
	}
	got := ShannonEntropy(string(input))
	if got < 4.0 {
		t.Errorf("256 raw bytes should have entropy > 4.0 (rune-based), got %f", got)
	}
}

func TestExtractCandidates_VeryLongLine(t *testing.T) {
	line := strings.Repeat("a", 100_000) + " token=" + strings.Repeat("x", 40)
	candidates := ExtractCandidates(line, 16)
	_ = candidates
}

func TestExtractCandidates_EmptyLine(t *testing.T) {
	candidates := ExtractCandidates("", 16)
	if len(candidates) != 0 {
		t.Errorf("expected 0 candidates from empty line, got %d", len(candidates))
	}
}

func TestClassifyCharset_EmptyString(t *testing.T) {
	got := ClassifyCharset("")
	if got != "mixed" {
		t.Errorf("expected 'mixed' for empty string, got %q", got)
	}
}

func TestDetectContext_EmptyKey(t *testing.T) {
	got := DetectContext("")
	if got != "freetext" {
		t.Errorf("expected 'freetext' for empty key, got %q", got)
	}
}

// helpers for tests
const randomToken32 = "aB3xK9mZqR2nP7wLaB3xK9mZqR2nP7wL"
