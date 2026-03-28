// Package auth resolves API keys and platform URL for the BouncerFox CLI.
package auth

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/bouncerfox/cli/pkg/configdir"
)

const defaultPlatformURL = "https://api.bouncerfox.dev"

// ResolveAPIKey returns the API key from env var or credentials file.
// Priority: BOUNCERFOX_API_KEY env > ~/.config/bouncerfox/credentials.
// Returns "" if no key found.
func ResolveAPIKey() string {
	if key := os.Getenv("BOUNCERFOX_API_KEY"); key != "" {
		return key
	}
	data, err := os.ReadFile(credentialsPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
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
