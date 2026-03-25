// Package pathutil provides path matching utilities.
package pathutil

import (
	"path/filepath"
	"strings"
)

// MatchGlob matches a path against a pattern that supports ** for recursive
// matching. Falls back to filepath.Match for patterns without **.
func MatchGlob(pattern, name string) bool {
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
	for i := 0; i <= len(rest); i++ {
		ok, _ := filepath.Match(suffix, rest[i:])
		if ok {
			return true
		}
	}
	return false
}
