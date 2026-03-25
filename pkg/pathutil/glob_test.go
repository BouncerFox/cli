package pathutil

import "testing"

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		// Simple patterns without **
		{"*.md", "README.md", true},
		{"*.md", "main.go", false},
		{"vendor/*", "vendor/foo.go", true},

		// ** matches everything
		{"**", "anything", true},
		{"**/", "anything", true},

		// ** with suffix
		{"**/*.md", "docs/README.md", true},
		{"**/*.md", "a/b/c/file.md", true},
		{"**/*.md", "file.go", false},

		// ** with prefix
		{"vendor/**", "vendor/foo/bar.go", true},
		{"vendor/**", "src/vendor/foo.go", false},

		// ** with prefix and suffix
		{"vendor/**/*.go", "vendor/pkg/file.go", true},
		{"vendor/**/*.go", "vendor/file.go", true},
		{"vendor/**/*.go", "vendor/pkg/file.md", false},

		// Edge cases
		{"", "", true},
		{"*.generated.md", "foo.generated.md", true},
		{"*.generated.md", "foo.md", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.name, func(t *testing.T) {
			got := MatchGlob(tt.pattern, tt.name)
			if got != tt.want {
				t.Errorf("MatchGlob(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
			}
		})
	}
}
