package target

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

func TestDetect_EnvVarOverride(t *testing.T) {
	t.Setenv("BOUNCERFOX_TARGET", "github:custom/override")
	info := Detect(DetectOptions{ScanRoot: "/tmp/test"})
	if info.ID != "github:custom/override" {
		t.Errorf("expected env override, got %q", info.ID)
	}
}

func TestDetect_FlagOverride(t *testing.T) {
	info := Detect(DetectOptions{ScanRoot: "/tmp/test", TargetFlag: "github:flag/repo"})
	if info.ID != "github:flag/repo" {
		t.Errorf("expected flag override, got %q", info.ID)
	}
}

func TestDetect_LocalFallback(t *testing.T) {
	dir := t.TempDir()
	info := Detect(DetectOptions{ScanRoot: dir})
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(dir)))
	want := "local:" + hash
	if info.ID != want {
		t.Errorf("expected %q, got %q", want, info.ID)
	}
}

func TestDetect_ConfigTarget(t *testing.T) {
	info := Detect(DetectOptions{ScanRoot: "/tmp/test", ConfigTarget: "github:config/repo"})
	if info.ID != "github:config/repo" {
		t.Errorf("expected config target, got %q", info.ID)
	}
}

func TestDetect_TriggerCI(t *testing.T) {
	t.Setenv("CI", "true")
	info := Detect(DetectOptions{ScanRoot: "/tmp/test"})
	if info.Trigger != "ci" {
		t.Errorf("expected trigger=ci, got %q", info.Trigger)
	}
}

func TestDetect_TriggerLocal(t *testing.T) {
	os.Unsetenv("CI")
	os.Unsetenv("GITHUB_ACTIONS")
	info := Detect(DetectOptions{ScanRoot: "/tmp/test"})
	if info.Trigger != "local" {
		t.Errorf("expected trigger=local, got %q", info.Trigger)
	}
}
