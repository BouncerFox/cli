package github

import (
	"os/exec"
	"strings"
)

// runGitRemote runs `git remote get-url origin` and returns its output.
func runGitRemote() (string, error) {
	out, err := exec.Command("git", "remote", "get-url", "origin").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
