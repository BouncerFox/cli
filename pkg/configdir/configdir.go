// Package configdir provides the BouncerFox config directory path.
package configdir

import (
	"os"
	"path/filepath"
)

// Dir returns the config directory, respecting BOUNCERFOX_CONFIG_DIR.
func Dir() string {
	if d := os.Getenv("BOUNCERFOX_CONFIG_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "bouncerfox")
}
