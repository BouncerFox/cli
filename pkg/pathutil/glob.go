// Package pathutil provides path matching utilities.
package pathutil

import (
	"path/filepath"
	"strings"
)

// maxDoubleStars caps how many ** segments a pattern can contain to prevent
// exponential recursion from adversarial patterns.
const maxDoubleStars = 4

// MatchGlob matches a path against a pattern that supports ** for recursive
// matching. Handles multiple ** segments. Falls back to filepath.Match for
// patterns without **.
func MatchGlob(pattern, name string) bool {
	if strings.Count(pattern, "**") > maxDoubleStars {
		return false
	}
	return matchGlob(pattern, name)
}

func matchGlob(pattern, name string) bool {
	if !strings.Contains(pattern, "**") {
		ok, _ := filepath.Match(pattern, name)
		return ok
	}
	parts := strings.SplitN(pattern, "**", 2)
	prefix := parts[0]
	suffix := parts[1]

	if prefix != "" && !strings.HasPrefix(name, prefix) {
		return false
	}
	rest := name[len(prefix):]

	if suffix == "" || suffix == "/" {
		return true
	}
	suffix = strings.TrimPrefix(suffix, "/")

	// Match suffix at each path segment boundary so ** only consumes whole
	// directory names (prevents "notestdata" matching a "testdata" pattern).
	if matchGlob(suffix, rest) {
		return true
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			if matchGlob(suffix, rest[i+1:]) {
				return true
			}
		}
	}
	return false
}
