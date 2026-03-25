// Package entropy provides Shannon entropy analysis for secret detection.
package entropy

import (
	"math"
	"regexp"
	"strings"
)

var (
	hexRe   = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	b64Re   = regexp.MustCompile(`^[a-zA-Z0-9+/]+=*$`)
	uuidRe  = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	tokenRe = regexp.MustCompile(`[a-zA-Z0-9+/=_-]+`)

	// CredentialKeyRe matches credential-like key names.
	CredentialKeyRe = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|passwd|credential|auth)`)
)

// ShannonEntropy computes Shannon entropy in bits per character.
// Returns 0.0 for empty strings or strings with only one unique character.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}
	if len(counts) == 1 {
		return 0.0
	}
	length := float64(total)
	var ent float64
	for _, count := range counts {
		p := float64(count) / length
		ent -= p * math.Log2(p)
	}
	return ent
}

// ClassifyCharset returns "hex", "base64", or "mixed" based on the characters in s.
func ClassifyCharset(s string) string {
	if hexRe.MatchString(s) {
		return "hex"
	}
	if b64Re.MatchString(s) {
		return "base64"
	}
	return "mixed"
}

// DetectContext returns "credential" if the line matches a credential key pattern,
// otherwise "freetext".
func DetectContext(line string) string {
	if CredentialKeyRe.MatchString(line) {
		return "credential"
	}
	return "freetext"
}

// ExtractCandidates extracts candidate secret strings from a line.
// Tokens must be at least minLength characters. UUIDs, git SHAs, SHA-256 hashes,
// URLs, file paths, and Windows path segments are filtered out.
func ExtractCandidates(line string, minLength int) []string {
	matches := tokenRe.FindAllStringIndex(line, -1)
	var candidates []string
	for _, loc := range matches {
		start, end := loc[0], loc[1]
		token := line[start:end]
		if len(token) < minLength {
			continue
		}
		if strings.Contains(token, "://") {
			continue
		}
		if strings.Contains(token, "/") {
			continue
		}
		// Exclude tokens preceded by backslash (Windows paths)
		if start > 0 && line[start-1] == '\\' {
			continue
		}
		if uuidRe.MatchString(token) {
			continue
		}
		// Exclude 40-char hex (git SHAs) and 64-char hex (SHA-256)
		if (len(token) == 40 || len(token) == 64) && hexRe.MatchString(token) {
			continue
		}
		candidates = append(candidates, token)
	}
	return candidates
}
