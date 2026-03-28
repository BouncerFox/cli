package configdir

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDir_Default(t *testing.T) {
	t.Setenv("BOUNCERFOX_CONFIG_DIR", "")
	dir := Dir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir")
	}
	want := filepath.Join(home, ".config", "bouncerfox")
	if dir != want {
		t.Errorf("Dir() = %q, want %q", dir, want)
	}
}

func TestDir_EnvOverride(t *testing.T) {
	t.Setenv("BOUNCERFOX_CONFIG_DIR", "/custom/path")
	dir := Dir()
	if dir != "/custom/path" {
		t.Errorf("Dir() = %q, want %q", dir, "/custom/path")
	}
}
