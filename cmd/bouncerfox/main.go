package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/bouncerfox/cli/pkg/auth"
	"github.com/bouncerfox/cli/pkg/config"
	"github.com/bouncerfox/cli/pkg/custom"
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

// platformEnabled gates connected mode (config pull, upload, verdicts).
// Set to true when the BouncerFox platform is live.
var platformEnabled = false

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
	rootCmd.AddCommand(newAuthCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newCompletionCmd())
	rootCmd.AddCommand(newVersionCmd())

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
		verboseFlag     bool
		noColorFlag     bool
		groupByFlag     string
		ignorePatterns  []string
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
			var cfg *config.Config
			var err error
			if configFlag != "" {
				cfg, err = config.LoadProjectConfig(filepath.Dir(configFlag))
			} else {
				cfg, err = config.LoadConfig(".")
			}
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// Merge CLI --ignore patterns into config.
			cfg.Ignore = append(cfg.Ignore, ignorePatterns...)

			// Connected mode detection.
			apiKey := auth.ResolveAPIKey()
			connected := platformEnabled && apiKey != ""
			platformURL := auth.PlatformURL()

			if !platformEnabled && apiKey != "" {
				fmt.Fprintln(os.Stderr, "note: connected mode is coming soon — running in offline mode")
			}

			// Connected mode: create platform client with HTTPS + domain validation.
			var pc *platform.HTTPClient
			if connected {
				var clientErr error
				pc, clientErr = platform.NewHTTPClient(platformURL, apiKey)
				if clientErr != nil {
					return clientErr
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
			var platformRulesVersion string
			if connected && !dryRunUpload {
				cache := platform.NewConfigCache(platform.DefaultCacheDir())
				skipCache := noCacheFlag || tgt.Trigger == "ci"

				var etag string
				if !skipCache {
					if entry, ok := cache.Load(tgt.ID); ok {
						// Cache hit — use cached config.
						if remoteCfg, rv, parseErr := config.ParsePlatformConfig([]byte(entry.Body)); parseErr == nil {
							cfg = remoteCfg
							platformRulesVersion = rv
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
				switch {
				case pullErr != nil:
					fmt.Fprintf(os.Stderr, "warning: config pull failed: %v (using local config)\n", pullErr)
				case pullResp.NotModified:
					// Cache is still valid; configHash already set above.
				default:
					// Fresh config from platform.
					if remoteCfg, rv, parseErr := config.ParsePlatformConfig([]byte(pullResp.Body)); parseErr != nil {
						fmt.Fprintf(os.Stderr, "warning: could not parse platform config: %v (using local config)\n", parseErr)
					} else {
						cfg = remoteCfg
						platformRulesVersion = rv
						configHash = hashString(pullResp.Body)
						cache.Store(tgt.ID, pullResp.Body, pullResp.ETag)
					}
				}

				// Warn if the platform expects a different built-in rules version.
				if platformRulesVersion != "" && platformRulesVersion != rules.RulesVersion {
					fmt.Fprintf(os.Stderr, "warning: rules version mismatch: local=%s platform=%s\n", rules.RulesVersion, platformRulesVersion)
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

			// Validate --group-by flag.
			switch groupByFlag {
			case "", "file", "rule", "severity":
				// valid
			default:
				return fmt.Errorf("unknown group-by %q: must be one of file, rule, severity", groupByFlag)
			}

			// Record scan start time.
			scanStart := time.Now()

			// Collect governed files.
			var docs []*document.ConfigDocument
			fileCount := 0
			skippedCount := 0
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
						skippedCount++
						return nil
					}

					// Check ignore patterns from config against both original and resolved paths.
					relPath, _ := filepath.Rel(absRoot, path)
					relReal, _ := filepath.Rel(absRoot, absReal)
					for _, pattern := range cfg.Ignore {
						if pathutil.MatchGlob(pattern, filepath.Base(path)) || pathutil.MatchGlob(pattern, relPath) {
							return nil
						}
						if relReal != relPath {
							if pathutil.MatchGlob(pattern, filepath.Base(absReal)) || pathutil.MatchGlob(pattern, relReal) {
								return nil
							}
						}
					}

					if !parser.IsGovernedFile(path) {
						return nil
					}

					// Enforce max file count on governed files only.
					fileCount++
					if fileCount >= maxFileCount {
						fmt.Fprintf(os.Stderr, "warning: file limit (%d) reached; stopping scan\n", maxFileCount)
						return errStopWalk
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
						skippedCount++
						return nil
					}

					content, err := os.ReadFile(path) //nolint:gosec // G304: reading user-provided config file
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

			// Compile custom rules from platform config.
			for _, cr := range cfg.CustomRules {
				if len(cr.MatchConfig) == 0 {
					continue
				}
				ruleMap := map[string]any{
					"id":          cr.RuleID,
					"name":        cr.Name,
					"severity":    cr.Severity,
					"remediation": cr.Description,
					"match":       cr.MatchConfig,
				}
				checkFn, compileErr := custom.Compile(ruleMap)
				if compileErr != nil {
					fmt.Fprintf(os.Stderr, "warning: could not compile custom rule %s: %v\n", cr.RuleID, compileErr)
					continue
				}
				opts.CustomChecks = append(opts.CustomChecks, engine.CustomCheck{
					RuleID:      cr.RuleID,
					Name:        cr.Name,
					Severity:    document.FindingSeverity(cr.Severity),
					FileTypes:   cr.FileTypes,
					Remediation: cr.Description,
					Check:       checkFn,
				})
			}

			// Run scan.
			result := engine.Scan(ctx, docs, opts)

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
				fmtOpts := output.FormatOptions{
					Verbose:  verboseFlag,
					NoColor:  noColorFlag,
					IsTTY:    output.IsTerminalStdout(),
					ScanRoot: absRootFirst,
					GroupBy:  groupByFlag,
					Stats: output.ScanStats{
						FilesScanned: result.FilesScanned,
						RulesRun:     result.RulesRun,
						Skipped:      skippedCount,
						Duration:     scanDuration,
					},
				}
				if groupByFlag == "rule" {
					ruleNames := make(map[string]string, len(rules.Registry)+len(opts.CustomChecks))
					for i := range rules.Registry {
						r := &rules.Registry[i]
						ruleNames[r.ID] = r.Name
					}
					for _, cc := range opts.CustomChecks {
						ruleNames[cc.RuleID] = cc.Name
					}
					fmtOpts.RuleNames = ruleNames
				}
				if err := output.FormatTable(result.Findings, os.Stdout, fmtOpts); err != nil {
					return fmt.Errorf("formatting output: %w", err)
				}
			}

			// GitHub PR feedback.
			if githubComment && !connected {
				token := os.Getenv("GITHUB_TOKEN")
				if token == "" {
					fmt.Fprintln(os.Stderr, "warning: --github-comment requires GITHUB_TOKEN env var")
				} else {
					owner, repo, err := gh.DetectRepoInfo(ctx)
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

						// Post check run if we have a commit SHA.
						if tgt.Commit != "" {
							if err := gh.PostCheckRun(ctx, gh.CheckRunOptions{
								Token: token, Owner: owner, Repo: repo,
								CommitSHA:  tgt.Commit,
								Findings:   result.Findings,
								Conclusion: gh.DeriveConclusion(result.Findings),
							}); err != nil {
								fmt.Fprintf(os.Stderr, "warning: check run failed: %v\n", err)
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

				// In connected mode, detect PR number and extract skills.
				if connected {
					pr, _ := gh.DetectPRNumber(prNumber)
					if pr > 0 {
						uploadReq.PRNumber = pr
					}
					uploadReq.Skills = upload.ExtractSkillMetadata(docs)
				}

				if dryRunUpload {
					data, err := json.MarshalIndent(uploadReq, "", "  ")
					if err != nil {
						return fmt.Errorf("dry-run: marshal: %w", err)
					}
					_, _ = os.Stdout.Write(data)
					_, _ = fmt.Fprintln(os.Stdout)
					if len(result.Findings) > 0 {
						os.Exit(1)
					}
					return nil
				}

				verdict, uploadErr := pc.Upload(ctx, uploadReq)
				if uploadErr != nil {
					var superErr *platform.SupersededError
					var payErr *platform.PaymentRequiredError

					if errors.As(uploadErr, &superErr) {
						fmt.Fprintln(os.Stderr, "warning: scan superseded — a newer commit exists for this PR")
						if len(result.Findings) > 0 {
							os.Exit(1)
						}
						return nil
					}

					if errors.As(uploadErr, &payErr) {
						fmt.Fprintln(os.Stderr, "warning: subscription lapsed — falling back to local exit logic")
						if len(result.Findings) > 0 {
							os.Exit(1)
						}
						return nil
					}

					fmt.Fprintf(os.Stderr, "error: upload failed: %v\n", uploadErr)
					behavior := offlineBehavior
					if behavior == "" {
						if tgt.Trigger == "ci" {
							behavior = "fail-closed"
						} else {
							behavior = "warn"
						}
					}
					switch behavior {
					case "fail-closed":
						fmt.Fprintln(os.Stderr, "error: platform unreachable — verdict unknown")
						os.Exit(2)
					default: // "warn" — fall back to local exit logic
						fmt.Fprintln(os.Stderr, "warning: falling back to local exit logic")
						if len(result.Findings) > 0 {
							os.Exit(1)
						}
						return nil
					}
				}

				if verdict.FindingCount > 0 {
					fmt.Fprintf(os.Stderr, "Scan report: %s\n", verdict.ScanURL)
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
	cmd.Flags().StringVar(&offlineBehavior, "offline-behavior", "", "behavior when upload fails: warn or fail-closed (auto: fail-closed in CI, warn locally)")
	cmd.Flags().BoolVar(&noFloorFlag, "no-floor", false, "allow disabling critical floor rules")
	_ = cmd.Flags().MarkHidden("no-floor")
	cmd.Flags().BoolVarP(&verboseFlag, "verbose", "v", false, "show code frames with surrounding context")
	cmd.Flags().BoolVar(&noColorFlag, "no-color", false, "disable colors and unicode symbols")
	cmd.Flags().StringVar(&groupByFlag, "group-by", "file", "group findings by: file, rule, severity")
	cmd.Flags().StringArrayVar(&ignorePatterns, "ignore", nil, "gitignore-style globs to skip (repeatable)")

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
	if _, err := rand.Read(b[:]); err != nil {
		log.Fatalf("crypto/rand.Read failed: %v", err)
	}
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
	f, err := os.Open(exe) //nolint:gosec // G304: reading own binary for checksum
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
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

# ignore: gitignore-style globs to skip during scanning
ignore:
  - "node_modules/**"
  - "vendor/**"
  - ".git/**"
  - "plugins/marketplaces/**"

# rules: per-rule overrides (enabled, severity, params, file_types)
# rules:
#   SEC_001:
#     enabled: true
#     severity: critical
#   SEC_002:
#     file_types: [skill_md, claude_md]
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

// newAuthCmd returns the `bouncerfox auth` subcommand.
func newAuthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with the BouncerFox platform",
		// TODO: implement device code flow when platform launches
		// (browser-side code exchange, CLI polls for token — no key pasting needed)
		RunE: func(cmd *cobra.Command, args []string) error {
			if !platformEnabled {
				fmt.Fprintln(os.Stderr, "The BouncerFox platform is coming soon.")
				fmt.Fprintln(os.Stderr, "For now, set BOUNCERFOX_API_KEY as an environment variable when the platform is available.")
				return nil
			}

			platformURL := auth.PlatformURL()
			webURL := strings.Replace(platformURL, "api.", "app.", 1) + "/auth/cli"

			if err := validateBrowserURL(webURL); err != nil {
				return fmt.Errorf("unsafe auth URL: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Opening browser to %s...\n", webURL)
			_ = openBrowser(webURL)

			fmt.Fprint(os.Stderr, "Paste your API key: ")
			keyBytes, err := term.ReadPassword(int(os.Stdin.Fd())) //nolint:gosec // G115: Fd() fits in int on all supported platforms
			fmt.Fprintln(os.Stderr)                                // newline after hidden input
			if err != nil {
				return fmt.Errorf("reading API key: %w", err)
			}

			key := strings.TrimSpace(string(keyBytes))
			if key == "" {
				return fmt.Errorf("no API key provided")
			}

			if err := auth.SaveCredentials(key); err != nil {
				return fmt.Errorf("saving credentials: %w", err)
			}
			fmt.Fprintln(os.Stderr, "Authenticated. API key stored.")
			return nil
		},
	}
}

// validateBrowserURL checks that a URL is safe to open in the user's browser.
// Delegates to platform.ValidateURL for shared HTTPS + domain allowlist logic.
func validateBrowserURL(rawURL string) error {
	return platform.ValidateURL(rawURL)
}

// openBrowser opens the given URL in the system browser (best-effort).
func openBrowser(url string) error {
	for _, cmd := range []string{"xdg-open", "open", "rundll32"} {
		if err := exec.CommandContext(context.Background(), cmd, url).Start(); err == nil { //nolint:gosec // G204: intentional exec for auth browser open
			return nil
		}
	}
	return fmt.Errorf("could not open browser")
}

// newCompletionCmd returns the `bouncerfox completion` subcommand.
func newCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate a shell completion script for the specified shell.

To load completions:

  bash:
    eval "$(bouncerfox completion bash)"

  zsh:
    bouncerfox completion zsh > "${fpath[1]}/_bouncerfox"

  fish:
    bouncerfox completion fish | source

  powershell:
    bouncerfox completion powershell | Out-String | Invoke-Expression`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell %q", args[0])
			}
		},
	}
	return cmd
}

// newVersionCmd returns the `bouncerfox version` subcommand.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the scanner version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("bouncerfox %s\n", version)
		},
	}
}

// newConfigCmd returns the `bouncerfox config` subcommand group.
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage scanner configuration",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "refresh",
		Short: "Invalidate cached platform config",
		RunE: func(cmd *cobra.Command, args []string) error {
			cache := platform.NewConfigCache(platform.DefaultCacheDir())
			cache.InvalidateAll()
			fmt.Fprintln(os.Stderr, "Config cache cleared.")
			return nil
		},
	})
	return cmd
}
