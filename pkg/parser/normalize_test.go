package parser

import "testing"

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
