package parser

import (
	"strings"
	"testing"
)

func TestNormalizeContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"fullwidth to ascii", "ｒｍ　-rf", "rm -rf"},
		{"html entities", "&lt;script&gt;", "<script>"},
		{"html numeric entities", "&#60;script&#62;", "<script>"},
		{"combined", "ａｐｉ_key = &quot;secret&quot;", "api_key = \"secret\""},
		{"no change needed", "normal text", "normal text"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeContent(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeContent(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeContent_NullBytes(t *testing.T) {
	input := "hello\x00world"
	got := NormalizeContent(input)
	if !strings.Contains(got, "\x00") {
		t.Error("null bytes should not be stripped by normalization")
	}
}

func TestNormalizeContent_LargeInput(t *testing.T) {
	input := strings.Repeat("abcdefghij", 100_000)
	got := NormalizeContent(input)
	if len(got) != len(input) {
		t.Errorf("expected same length, got %d vs %d", len(got), len(input))
	}
}

func TestNormalizeContent_MixedUnicode(t *testing.T) {
	input := "ｒｍ &amp; &#60;script&#62;"
	got := NormalizeContent(input)
	if !strings.Contains(got, "rm") {
		t.Error("fullwidth chars should be normalized to ASCII")
	}
	if !strings.Contains(got, "&") {
		t.Error("HTML entities should be unescaped")
	}
}
