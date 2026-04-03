package github

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// runGitRemote runs `git remote get-url origin` and returns its output.
func runGitRemote(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "remote", "get-url", "origin").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
