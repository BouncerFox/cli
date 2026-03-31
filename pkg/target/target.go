package target

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Info holds the detected scan target identity.
type Info struct {
	ID      string // e.g. "github:bouncerfox/cli" or "local:<sha256>"
	Label   string // human-readable label (e.g. "bouncerfox/cli" or dir basename)
	Trigger string // "ci" or "local"
	Commit  string // git commit SHA (empty if not in git repo)
	Branch  string // git branch (empty if not in git repo)
}

// DetectOptions configures target detection.
type DetectOptions struct {
	ScanRoot     string // absolute path to scan root
	TargetFlag   string // --target flag value (highest priority after env)
	ConfigTarget string // target field from .bouncerfox.yml
	TriggerFlag  string // --trigger flag override
}

// Detect resolves the scan target identity.
// Priority: BOUNCERFOX_TARGET env > --target flag > config target > git remote > local hash.
func Detect(opts DetectOptions) Info {
	info := Info{
		Trigger: detectTrigger(opts.TriggerFlag),
	}

	if env := os.Getenv("BOUNCERFOX_TARGET"); env != "" {
		info.ID = env
		info.Label = labelFromID(env)
	} else if opts.TargetFlag != "" {
		info.ID = opts.TargetFlag
		info.Label = labelFromID(opts.TargetFlag)
	} else if opts.ConfigTarget != "" {
		info.ID = opts.ConfigTarget
		info.Label = labelFromID(opts.ConfigTarget)
	} else if slug := gitRemoteSlug(opts.ScanRoot); slug != "" {
		info.ID = "github:" + slug
		info.Label = slug
	} else {
		absPath, _ := filepath.Abs(opts.ScanRoot)
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(absPath)))
		info.ID = "local:" + hash
		info.Label = filepath.Base(absPath)
	}

	// Detect git info — prefer GitHub env vars in CI (reliable in shallow clones).
	if sha := os.Getenv("GITHUB_SHA"); sha != "" {
		info.Commit = sha
	} else {
		info.Commit = gitOutput(opts.ScanRoot, "rev-parse", "HEAD")
	}
	if ref := os.Getenv("GITHUB_REF_NAME"); ref != "" {
		info.Branch = ref
	} else {
		info.Branch = gitOutput(opts.ScanRoot, "branch", "--show-current")
	}

	return info
}

func detectTrigger(flagOverride string) string {
	if flagOverride != "" {
		return flagOverride
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("CI") == "true" {
		return "ci"
	}
	return "local"
}

func labelFromID(id string) string {
	if _, after, ok := strings.Cut(id, ":"); ok {
		return after
	}
	return id
}

func gitRemoteSlug(dir string) string {
	out := gitOutput(dir, "remote", "get-url", "origin")
	if out == "" {
		return ""
	}
	return parseGitRemoteSlug(out)
}

func parseGitRemoteSlug(remote string) string {
	// Handle SSH: git@github.com:org/repo.git
	if strings.HasPrefix(remote, "git@") {
		if idx := strings.Index(remote, ":"); idx >= 0 {
			slug := remote[idx+1:]
			slug = strings.TrimSuffix(slug, ".git")
			return slug
		}
	}
	// Handle HTTPS: https://github.com/org/repo.git
	remote = strings.TrimSuffix(remote, ".git")
	parts := strings.Split(remote, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}
	return ""
}

func gitOutput(dir string, args ...string) string {
	cmd := exec.Command("git", args...) //nolint:gosec // G204: git command with safe args
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
