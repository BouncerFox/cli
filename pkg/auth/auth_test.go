package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAPIKey_EnvVar(t *testing.T) {
	t.Setenv("BOUNCERFOX_API_KEY", "bf_abc123")
	key := ResolveAPIKey()
	if key != "bf_abc123" {
		t.Errorf("expected env var key, got %q", key)
	}
}

func TestResolveAPIKey_CredentialsFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BOUNCERFOX_CONFIG_DIR", dir)
	os.Unsetenv("BOUNCERFOX_API_KEY")

	credPath := filepath.Join(dir, "credentials")
	os.WriteFile(credPath, []byte("bf_fromfile\n"), 0o600)

	key := ResolveAPIKey()
	if key != "bf_fromfile" {
		t.Errorf("expected file key, got %q", key)
	}
}

func TestResolveAPIKey_Empty(t *testing.T) {
	os.Unsetenv("BOUNCERFOX_API_KEY")
	t.Setenv("BOUNCERFOX_CONFIG_DIR", t.TempDir())
	key := ResolveAPIKey()
	if key != "" {
		t.Errorf("expected empty, got %q", key)
	}
}

func TestIsConnected(t *testing.T) {
	t.Setenv("BOUNCERFOX_API_KEY", "bf_x")
	if !IsConnected() {
		t.Error("expected connected mode")
	}
}

func TestPlatformURL_Default(t *testing.T) {
	os.Unsetenv("BOUNCERFOX_PLATFORM_URL")
	if PlatformURL() != "https://api.bouncerfox.dev" {
		t.Errorf("unexpected default URL: %q", PlatformURL())
	}
}

func TestPlatformURL_EnvOverride(t *testing.T) {
	t.Setenv("BOUNCERFOX_PLATFORM_URL", "https://custom.example.com")
	if PlatformURL() != "https://custom.example.com" {
		t.Errorf("expected custom URL")
	}
}
