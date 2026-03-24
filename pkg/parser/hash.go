package parser

import (
	"crypto/sha256"
	"encoding/hex"
)

// ComputeContentHash returns the SHA-256 hex digest of content bytes.
func ComputeContentHash(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}
