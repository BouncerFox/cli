package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/bouncerfox/cli/pkg/auth"
	"github.com/bouncerfox/cli/pkg/config"
	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/engine"
	gh "github.com/bouncerfox/cli/pkg/github"
	"github.com/bouncerfox/cli/pkg/output"
	"github.com/bouncerfox/cli/pkg/parser"
	"github.com/bouncerfox/cli/pkg/pathutil"
	"github.com/bouncerfox/cli/pkg/platform"
	"github.com/bouncerfox/cli/pkg/rules"
	"github.com/bouncerfox/cli/pkg/target"
	"github.com/bouncerfox/cli/pkg/upload"
)

const (
	maxFileSize  = 1 * 1024 * 1024 // 1 MB
	maxFileCount = 500
	scanTimeout  = 5 * time.Minute
)

// errStopWalk is a sentinel returned from the Walk callback to stop iteration
// when the file count limit is reached.
var errStopWalk = errors.New("file limit reached")

var version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:     "bouncerfox",
		Short:   "BouncerFox — AI agent config scanner",
		Version: version,
	}

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newRulesCmd())
	rootCmd.AddCommand(newInitCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

// newScanCmd returns the `bouncerfox scan [paths...]` subcommand.
func newScanCmd() *cobra.Command {
	var (
		formatFlag      string
		severityFlag    string
		configFlag      string
		maxFindingsFlag int
		githubComment   bool
		prNumber        int
		dryRunUpload    bool
		stripPaths      bool
		anonymous       bool
		noCacheFlag     bool
		targetFlag      string
		triggerFlag     string
		offlineBehavior string
		noFloorFlag     bool
	)

	cmd := &cobra.Command{
		Use:   "scan [paths...]",
		Short: "Scan files for security and quality issues",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Determine paths to scan; default to ".".
			paths := args
			if len(paths) == 0 {
				paths = []string{"."}
			}

			// Load local config.
			configDir := "."
			if configFlag != "" {
				configDir = filepath.Dir(configFlag)
			}
			cfg, err := config.LoadConfig(configDir)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// Connected mode detection.
			apiKey := auth.ResolveAPIKey()
			connected := apiKey != ""
			platformURL := auth.PlatformURL()

			// Validate HTTPS for connected mode.
			if connected {
				if err := platform.ValidateHTTPS(platformURL); err != nil {
					return err
				}
			}

			// Detect scan target (needed for both modes).
			absRootFirst, _ := filepath.Abs(paths[0])
			tgt := target.Detect(target.DetectOptions{
				ScanRoot:     absRootFirst,
				TargetFlag:   targetFlag,
				ConfigTarget: cfg.Target,
				TriggerFlag:  triggerFlag,
			})

			// Wrap the entire scan in a timeout context.
			ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
			defer cancel()

			// Connected mode: pull config from platform (before scan, after local config load).
			var configHash string
			var pc *platform.HTTPClient
			if connected {
				pc = platform.NewHTTPClient(platformURL, apiKey)
			}
			if connected && !dryRunUpload {
				cache := platform.NewConfigCache(platform.DefaultCacheDir())
				skipCache := noCacheFlag || tgt.Trigger == "ci"

				var etag string
				if !skipCache {
					if entry, ok := cache.Load(tgt.ID); ok {
						// Cache hit — use cached config.
						if remoteCfg, parseErr := config.ParseConfigBytes([]byte(entry.Body)); parseErr == nil {
							cfg = remoteCfg
							configHash = hashString(entry.Body)
						}
						etag = entry.ETag
					}
				}

				// Pull fresh config (or validate cache with ETag).
				pullResp, pullErr := pc.PullConfig(ctx, platform.PullConfigRequest{
					Target: tgt.ID,
					ETag:   etag,
				})
				if pullErr != nil {
					fmt.Fprintf(os.Stderr, "warning: config pull failed: %v (using local config)\n", pullErr)
				} else if pullResp.NotModified {
					// Cache is still valid; configHash already set above.
				} else {
					// Fresh config from platform.
					if remoteCfg, parseErr := config.ParseConfigBytes([]byte(pullResp.Body)); parseErr != nil {
						fmt.Fprintf(os.Stderr, "warning: could not parse platform config: %v (using local config)\n", parseErr)
					} else {
						cfg = remoteCfg
						configHash = hashString(pullResp.Body)
						cache.Store(tgt.ID, pullResp.Body, pullResp.ETag)
					}
				}
			}

			// Apply CLI-only overrides after all config resolution.
			cfg.NoFloor = noFloorFlag
			if severityFlag != "" {
				sv := document.FindingSeverity(severityFlag)
				if sv.Level() < 0 {
					return fmt.Errorf("unknown severity %q: must be one of info, warn, high, critical", severityFlag)
				}
				cfg.SeverityFloor = sv
			}

			// Record scan start time.
			scanStart := time.Now()

			// Collect governed files.
			var docs []*document.ConfigDocument
			fileCount := 0
			for _, root := range paths {
				// Resolve the scan root to an absolute path for containment checks.
				absRoot, err := filepath.Abs(root)
				if err != nil {
					return fmt.Errorf("resolving path %s: %w", root, err)
				}

				err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
					// Respect scan timeout.
					if ctx.Err() != nil {
						return ctx.Err()
					}

					if walkErr != nil {
						return walkErr
					}

					// Skip .git directories.
					if d.IsDir() {
						if d.Name() == ".git" {
							return filepath.SkipDir
						}
						return nil
					}

					// Enforce max file count (counts all files, not just governed ones).
					fileCount++
					if fileCount >= maxFileCount {
						fmt.Fprintf(os.Stderr, "warning: file limit (%d) reached; stopping scan\n", maxFileCount)
						return errStopWalk
					}

					// Resolve symlinks and verify the real path is within the scan root.
					realPath, err := filepath.EvalSymlinks(path)
					if err != nil {
						fmt.Fprintf(os.Stderr, "warning: could not resolve %s: %v\n", path, err)
						return nil
					}
					absReal, err := filepath.Abs(realPath)
					if err != nil {
						fmt.Fprintf(os.Stderr, "warning: could not get absolute path for %s: %v\n", realPath, err)
						return nil
					}
					// Reject files whose real path escapes the scan root.
					rel, err := filepath.Rel(absRoot, absReal)
					if err != nil || rel == ".." || (len(rel) >= 3 && rel[:3] == "../") {
						fmt.Fprintf(os.Stderr, "warning: skipping %s: resolves outside scan root\n", path)
						return nil
					}

					// Enforce max file size.
					// NOTE: TOCTOU between this check and ReadFile below is accepted for a local CLI tool.
					info, err := d.Info()
					if err != nil {
						fmt.Fprintf(os.Stderr, "warning: could not stat %s: %v\n", path, err)
						return nil
					}
					if info.Size() > maxFileSize {
						fmt.Fprintf(os.Stderr, "warning: skipping %s: file too large (%d bytes)\n", path, info.Size())
						return nil
					}

					// Check ignore patterns from config.
					relPath, _ := filepath.Rel(absRoot, path)
					for _, pattern := range cfg.Ignore {
						if pathutil.MatchGlob(pattern, filepath.Base(path)) || pathutil.MatchGlob(pattern, relPath) {
							return nil
						}
					}

					if !parser.IsGovernedFile(path) {
						return nil
					}

					content, err := os.ReadFile(path)
					if err != nil {
						fmt.Fprintf(os.Stderr, "warning: could not read %s: %v\n", path, err)
						return nil
					}

					doc := parser.RouteAndParse(path, string(content))
					if doc != nil {
						docs = append(docs, doc)
					}
					return nil
				})
				if err == errStopWalk {
					break
				}
				if err != nil {
					if ctx.Err() != nil {
						fmt.Fprintf(os.Stderr, "warning: scan timed out after %s\n", scanTimeout)
						break
					}
					return fmt.Errorf("walking %s: %w", root, err)
				}
			}

			// Build scan options from config.
			opts := cfg.ToScanOptions()
			if maxFindingsFlag > 0 {
				opts.MaxFindings = maxFindingsFlag
			}

			// Run scan.
			result := engine.Scan(docs, opts)

			// Compute scan duration.
			scanDuration := time.Since(scanStart)

			// Format and write output.
			switch formatFlag {
			case "json":
				if err := output.FormatJSON(result.Findings, os.Stdout); err != nil {
					return fmt.Errorf("formatting output: %w", err)
				}
			case "sarif":
				if err := output.FormatSARIF(result.Findings, os.Stdout); err != nil {
					return fmt.Errorf("formatting output: %w", err)
				}
			default: // "table" or empty
				if err := output.FormatTable(result.Findings, os.Stdout); err != nil {
					return fmt.Errorf("formatting output: %w", err)
				}
			}

			// GitHub PR feedback.
			if githubComment {
				token := os.Getenv("GITHUB_TOKEN")
				if token == "" {
					fmt.Fprintln(os.Stderr, "warning: --github-comment requires GITHUB_TOKEN env var")
				} else {
					owner, repo, err := gh.DetectRepoInfo()
					if err != nil {
						fmt.Fprintf(os.Stderr, "warning: could not detect repo info: %v\n", err)
					} else {
						pr, _ := gh.DetectPRNumber(prNumber)
						if pr > 0 {
							if err := gh.PostPRComment(ctx, gh.CommentOptions{
								Token: token, Owner: owner, Repo: repo,
								PRNumber: pr, Findings: result.Findings,
							}); err != nil {
								fmt.Fprintf(os.Stderr, "warning: PR comment failed: %v\n", err)
							}
						}
					}
				}
			}

			// Connected mode: upload findings and use verdict for exit code.
			if connected || dryRunUpload {
				wireFindings := upload.BuildWireFindings(result.Findings, stripPaths, anonymous)

				fps := make([]string, len(wireFindings))
				for i, wf := range wireFindings {
					fps[i] = wf.Fingerprint
				}

				// Non-git scans need a UUID nonce for idempotency.
				commitForKey := tgt.Commit
				if commitForKey == "" {
					commitForKey = uuidV4()
				}
				idemKey := upload.IdempotencyKey(tgt.ID, commitForKey, configHash, fps)

				uploadReq := platform.UploadRequest{
					Version:        upload.Version,
					CLIVersion:     version,
					CLIChecksum:    binaryChecksum(),
					Trigger:        tgt.Trigger,
					Timestamp:      scanStart.UTC().Format(time.RFC3339),
					DurationMs:     int(scanDuration.Milliseconds()),
					TotalFiles:     fileCount,
					ScannedFiles:   result.FilesScanned,
					Profile:        cfg.Profile,
					ConfigHash:     configHash,
					Findings:       wireFindings,
					IdempotencyKey: idemKey,
				}

				if !anonymous {
					uploadReq.Target = tgt.ID
					uploadReq.TargetLabel = tgt.Label
					uploadReq.CommitSHA = tgt.Commit
					uploadReq.Branch = tgt.Branch
				}

				if dryRunUpload {
					data, err := json.MarshalIndent(uploadReq, "", "  ")
					if err != nil {
						return fmt.Errorf("dry-run: marshal: %w", err)
					}
					_, _ = os.Stdout.Write(data)
					fmt.Fprintln(os.Stdout)
					if len(result.Findings) > 0 {
						os.Exit(1)
					}
					return nil
				}

				verdict, uploadErr := pc.Upload(ctx, uploadReq)
				if uploadErr != nil {
					fmt.Fprintf(os.Stderr, "error: upload failed: %v\n", uploadErr)
					// Handle offline behavior.
					switch offlineBehavior {
					case "fail-closed":
						os.Exit(2)
					default: // "warn" — fall back to local exit logic
						fmt.Fprintln(os.Stderr, "warning: falling back to local exit logic")
						if len(result.Findings) > 0 {
							os.Exit(1)
						}
						return nil
					}
				}

				if verdict.DashboardURL != "" {
					fmt.Fprintf(os.Stderr, "Dashboard: %s\n", verdict.DashboardURL)
				}
				for _, r := range verdict.Reasons {
					fmt.Fprintf(os.Stderr, "  [%s] %s: %s\n", r.Rule, r.Policy, r.Message)
				}

				os.Exit(verdict.ExitCode())
			}

			// Standalone mode: findings > 0 means exit 1.
			if len(result.Findings) > 0 {
				fmt.Fprintln(os.Stderr, "View trends and enforce team policy \u2192 bouncerfox auth")
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "output format: table, json, sarif")
	cmd.Flags().StringVarP(&severityFlag, "severity", "s", "", "severity floor override: critical, high, warn, info")
	cmd.Flags().StringVarP(&configFlag, "config", "c", "", "config file path (overrides auto-discovery)")
	cmd.Flags().IntVar(&maxFindingsFlag, "max-findings", 0, "cap total findings (0 = unlimited)")
	cmd.Flags().BoolVar(&githubComment, "github-comment", false, "post findings as PR comment (requires GITHUB_TOKEN)")
	cmd.Flags().IntVar(&prNumber, "pr-number", 0, "PR number for GitHub comment (auto-detected in CI)")
	cmd.Flags().BoolVar(&dryRunUpload, "dry-run-upload", false, "preview upload payload without sending")
	cmd.Flags().BoolVar(&stripPaths, "strip-paths", false, "send filenames only in upload (no full paths)")
	cmd.Flags().BoolVar(&anonymous, "anonymous", false, "strip all identifying info from upload")
	cmd.Flags().BoolVar(&noCacheFlag, "no-cache", false, "skip config cache (always pull fresh)")
	cmd.Flags().StringVar(&targetFlag, "target", "", "override scan target identity")
	cmd.Flags().StringVar(&triggerFlag, "trigger", "", "override trigger detection (ci or local)")
	cmd.Flags().StringVar(&offlineBehavior, "offline-behavior", "warn", "behavior when upload fails: warn or fail-closed")
	cmd.Flags().BoolVar(&noFloorFlag, "no-floor", false, "allow disabling critical floor rules")
	_ = cmd.Flags().MarkHidden("no-floor")

	return cmd
}

// hashString returns the hex-encoded SHA-256 of s.
func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// uuidV4 generates a random UUID v4 string without external dependencies.
func uuidV4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// binaryChecksum returns the SHA-256 hex digest of the running binary.
// Returns "" if the binary cannot be read.
func binaryChecksum() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// newRulesCmd returns the `bouncerfox rules` subcommand.
func newRulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rules",
		Short: "List all registered rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("%-10s %-10s %-15s %s\n", "ID", "SEVERITY", "CATEGORY", "DESCRIPTION")
			fmt.Printf("%-10s %-10s %-15s %s\n", "----------", "----------", "---------------", "-----------")
			for i := range rules.Registry {
				r := &rules.Registry[i]
				fmt.Printf("%-10s %-10s %-15s %s\n",
					r.ID,
					string(r.DefaultSeverity),
					r.Category,
					r.Description,
				)
			}
			return nil
		},
	}
}

// defaultConfigContent is the template written by `bouncerfox init`.
const defaultConfigContent = `# .bouncerfox.yml — BouncerFox scanner configuration
# Generated by: bouncerfox init

# profile: "recommended" (default) enables the recommended rule set.
# Use "all_rules" to enable every rule including informational ones.
profile: recommended

# severity_floor: minimum severity level to report.
# Possible values: info, warn, high, critical (empty = report everything)
severity_floor: ""

# ignore: list of gitignore-style glob patterns to skip.
ignore: []
  # - "vendor/**"
  # - "**/*.generated.md"

# rules: per-rule overrides.
# rules:
#   SEC_001:
#     enabled: true
#     severity: critical
#   QA_001:
#     enabled: false
`

// newInitCmd returns the `bouncerfox init` subcommand.
func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Generate a default .bouncerfox.yml config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			const configFile = ".bouncerfox.yml"
			if _, err := os.Stat(configFile); err == nil {
				return fmt.Errorf("%s already exists; remove it first to regenerate", configFile)
			}
			if err := os.WriteFile(configFile, []byte(defaultConfigContent), 0o600); err != nil {
				return fmt.Errorf("writing %s: %w", configFile, err)
			}
			fmt.Printf("Created %s\n", configFile)
			return nil
		},
	}
}
