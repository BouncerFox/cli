// Package auth resolves API keys and platform URL for the BouncerFox CLI.
package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bouncerfox/cli/pkg/configdir"
)

const defaultPlatformURL = "https://api.bouncerfox.dev"

// ResolveAPIKey returns the API key from env var or credentials file.
// Priority: BOUNCERFOX_API_KEY env > ~/.config/bouncerfox/credentials.
// Returns "" if no key found or the key has an invalid format.
func ResolveAPIKey() string {
	if key := os.Getenv("BOUNCERFOX_API_KEY"); key != "" {
		if ValidateAPIKeyFormat(key) != nil {
			return ""
		}
		return key
	}
	path := credentialsPath()
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is derived from known config directory, not user input
	if err != nil {
		return ""
	}

	// Warn if credentials file has overly broad permissions.
	if info, statErr := os.Stat(path); statErr == nil {
		mode := info.Mode()
		if mode&0o077 != 0 {
			fmt.Fprintf(os.Stderr, "warning: credentials file %s has overly broad permissions (%o), expected 0600\n", path, mode.Perm())
		}
	}

	key := strings.TrimSpace(string(data))
	if ValidateAPIKeyFormat(key) != nil {
		return ""
	}
	return key
}

// ValidateAPIKeyFormat rejects API keys containing control characters that
// could cause header injection or protocol-level parsing issues.
func ValidateAPIKeyFormat(key string) error {
	for _, c := range key {
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("API key contains invalid control character (0x%02x)", c)
		}
	}
	return nil
}

// IsConnected returns true if an API key is available (connected mode).
func IsConnected() bool {
	return ResolveAPIKey() != ""
}

// PlatformURL returns the platform URL from env var or default.
func PlatformURL() string {
	if u := os.Getenv("BOUNCERFOX_PLATFORM_URL"); u != "" {
		return u
	}
	return defaultPlatformURL
}

func credentialsPath() string {
	return filepath.Join(configdir.Dir(), "credentials")
}

// SaveCredentials writes the API key to the credentials file.
func SaveCredentials(apiKey string) error {
	dir := configdir.Dir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(credentialsPath(), []byte(apiKey+"\n"), 0o600)
}
