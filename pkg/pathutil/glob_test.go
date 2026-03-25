package pathutil

import (
	"strings"
	"testing"
)

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

// TestMatchGlob_PathTraversal documents that MatchGlob treats ".." as a normal
// path segment. Callers that need traversal protection must sanitize paths
// before calling MatchGlob.
func TestMatchGlob_PathTraversal(t *testing.T) {
	if !MatchGlob("**/*.md", "../secret.md") {
		t.Error("expected '..' to be treated as a normal segment and match")
	}
}

func TestMatchGlob_VeryLongPath(t *testing.T) {
	path := strings.Repeat("a/", 1000) + "file.md"
	_ = MatchGlob("**/*.md", path)
}
