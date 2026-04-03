package auth

import (
	"bytes"
	"io"
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

func TestResolveAPIKey_CredentialsFile0644WarnsPermissions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BOUNCERFOX_CONFIG_DIR", dir)
	os.Unsetenv("BOUNCERFOX_API_KEY")

	credPath := filepath.Join(dir, "credentials")
	if err := os.WriteFile(credPath, []byte("bf_test_key\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Capture stderr to check for warning.
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	key := ResolveAPIKey()

	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if key != "bf_test_key" {
		t.Errorf("expected key 'bf_test_key', got %q", key)
	}
	if !bytes.Contains(buf.Bytes(), []byte("overly broad permissions")) {
		t.Error("expected warning about overly broad permissions on stderr")
	}
}

func TestResolveAPIKey_CredentialsFile0600NoWarning(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BOUNCERFOX_CONFIG_DIR", dir)
	os.Unsetenv("BOUNCERFOX_API_KEY")

	credPath := filepath.Join(dir, "credentials")
	if err := os.WriteFile(credPath, []byte("bf_safe_key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Capture stderr.
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	key := ResolveAPIKey()

	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if key != "bf_safe_key" {
		t.Errorf("expected key 'bf_safe_key', got %q", key)
	}
	if bytes.Contains(buf.Bytes(), []byte("overly broad permissions")) {
		t.Error("did not expect warning about permissions for 0600 file")
	}
}

func TestValidateAPIKeyFormat_Newline(t *testing.T) {
	err := ValidateAPIKeyFormat("bf_key\ninjection")
	if err == nil {
		t.Error("expected error for API key with newline")
	}
}

func TestValidateAPIKeyFormat_CarriageReturn(t *testing.T) {
	err := ValidateAPIKeyFormat("bf_key\rinjection")
	if err == nil {
		t.Error("expected error for API key with carriage return")
	}
}

func TestValidateAPIKeyFormat_NullByte(t *testing.T) {
	err := ValidateAPIKeyFormat("bf_key\x00injection")
	if err == nil {
		t.Error("expected error for API key with null byte")
	}
}

func TestValidateAPIKeyFormat_Valid(t *testing.T) {
	err := ValidateAPIKeyFormat("bf_abc123_valid_key")
	if err != nil {
		t.Errorf("unexpected error for valid key: %v", err)
	}
}

func TestResolveAPIKey_RejectsKeyWithNewline(t *testing.T) {
	t.Setenv("BOUNCERFOX_API_KEY", "bf_key\ninjection")
	key := ResolveAPIKey()
	if key != "" {
		t.Errorf("expected empty key for invalid format, got %q", key)
	}
}
