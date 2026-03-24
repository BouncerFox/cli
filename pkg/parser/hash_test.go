package parser

import "testing"

func TestComputeContentHash(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			"empty",
			"",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			"hello world",
			"hello world",
			"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeContentHash([]byte(tt.content))
			if got != tt.want {
				t.Errorf("ComputeContentHash(%q) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}
