package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "bouncerfox-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)

	binaryPath = filepath.Join(tmp, "bouncerfox")
	build := exec.Command("go", "build", "-o", binaryPath, "./")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		panic("build failed: " + string(out))
	}

	os.Exit(m.Run())
}

func runBinary(t *testing.T, args []string, env ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	cmd.Env = append(os.Environ(), env...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run binary: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

func TestSmoke_ScanClean(t *testing.T) {
	_, _, code := runBinary(t, []string{"scan", "testdata/clean-skill"})
	if code != 0 {
		t.Errorf("scan clean-skill: expected exit 0, got %d", code)
	}
}

func TestSmoke_Rules(t *testing.T) {
	stdout, _, code := runBinary(t, []string{"rules"})
	if code != 0 {
		t.Errorf("rules: expected exit 0, got %d", code)
	}
	if !bytes.Contains([]byte(stdout), []byte("SEC_001")) {
		t.Error("rules output should contain SEC_001")
	}
}

func TestSmoke_Init(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(binaryPath, "init")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("init failed: %s", out)
	}
	data, err := os.ReadFile(filepath.Join(dir, ".bouncerfox.yml"))
	if err != nil {
		t.Fatal("init did not create .bouncerfox.yml")
	}
	if !bytes.Contains(data, []byte("profile: recommended")) {
		t.Error("init config should contain 'profile: recommended'")
	}
}

func TestSmoke_Version(t *testing.T) {
	stdout, _, code := runBinary(t, []string{"version"})
	if code != 0 {
		t.Errorf("version: expected exit 0, got %d", code)
	}
	if !bytes.Contains([]byte(stdout), []byte("bouncerfox")) {
		t.Error("version output should contain 'bouncerfox'")
	}
}

func TestSmoke_CompletionBash(t *testing.T) {
	stdout, _, code := runBinary(t, []string{"completion", "bash"})
	if code != 0 {
		t.Errorf("completion bash: expected exit 0, got %d", code)
	}
	if len(stdout) < 100 {
		t.Error("bash completion output seems too short")
	}
}

func TestSmoke_CompletionZsh(t *testing.T) {
	_, _, code := runBinary(t, []string{"completion", "zsh"})
	if code != 0 {
		t.Errorf("completion zsh: expected exit 0, got %d", code)
	}
}

func TestSmoke_CompletionFish(t *testing.T) {
	_, _, code := runBinary(t, []string{"completion", "fish"})
	if code != 0 {
		t.Errorf("completion fish: expected exit 0, got %d", code)
	}
}
