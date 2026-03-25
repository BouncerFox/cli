package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/bouncerfox/cli/pkg/config"
	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/engine"
	"github.com/bouncerfox/cli/pkg/output"
	"github.com/bouncerfox/cli/pkg/parser"
	"github.com/bouncerfox/cli/pkg/rules"
)

const (
	maxFileSize  = 1 * 1024 * 1024 // 1 MB
	maxFileCount = 500
	scanTimeout  = 5 * time.Minute
)

// errStopWalk is a sentinel returned from the Walk callback to stop iteration
// when the file count limit is reached.
var errStopWalk = fmt.Errorf("file limit reached")

var version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:     "bf",
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

// newScanCmd returns the `bf scan [paths...]` subcommand.
func newScanCmd() *cobra.Command {
	var (
		formatFlag      string
		severityFlag    string
		configFlag      string
		maxFindingsFlag int
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

			// Load config.
			configDir := "."
			if configFlag != "" {
				configDir = filepath.Dir(configFlag)
			}
			cfg, err := config.LoadConfig(configDir)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// Apply --severity flag as severity floor override.
			if severityFlag != "" {
				sv := document.FindingSeverity(severityFlag)
				if sv.Level() < 0 {
					return fmt.Errorf("unknown severity %q: must be one of info, warn, high, critical", severityFlag)
				}
				cfg.SeverityFloor = sv
			}

			// Wrap the entire scan in a timeout context.
			ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
			defer cancel()

			// Collect governed files.
			var docs []*document.ConfigDocument
			fileCount := 0
		rootLoop:
			for _, root := range paths {
				// Resolve the scan root to an absolute path for containment checks.
				absRoot, err := filepath.Abs(root)
				if err != nil {
					return fmt.Errorf("resolving path %s: %w", root, err)
				}

				err = filepath.Walk(absRoot, func(path string, info os.FileInfo, walkErr error) error {
					// Respect scan timeout.
					if ctx.Err() != nil {
						return ctx.Err()
					}

					if walkErr != nil {
						return walkErr
					}

					// Skip .git directories.
					if info.IsDir() {
						if info.Name() == ".git" {
							return filepath.SkipDir
						}
						return nil
					}

					// Enforce max file count.
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
					if info.Size() > maxFileSize {
						fmt.Fprintf(os.Stderr, "warning: skipping %s: file too large (%d bytes)\n", path, info.Size())
						return nil
					}

					// Check ignore patterns from config.
					for _, pattern := range cfg.Ignore {
						matched, err := filepath.Match(pattern, filepath.Base(path))
						if err == nil && matched {
							return nil
						}
						// Also try matching the full relative path.
						matched, err = filepath.Match(pattern, path)
						if err == nil && matched {
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
					fileCount++
					return nil
				})
				if err == errStopWalk {
					break rootLoop
				}
				if err != nil {
					if ctx.Err() != nil {
						fmt.Fprintf(os.Stderr, "warning: scan timed out after %s\n", scanTimeout)
						break rootLoop
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

			// Exit code: 0 = no findings, 1 = findings found.
			if len(result.Findings) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "output format: table, json, sarif")
	cmd.Flags().StringVarP(&severityFlag, "severity", "s", "", "severity floor override: critical, high, warn, info")
	cmd.Flags().StringVarP(&configFlag, "config", "c", "", "config file path (overrides auto-discovery)")
	cmd.Flags().IntVar(&maxFindingsFlag, "max-findings", 0, "cap total findings (0 = unlimited)")

	return cmd
}

// newRulesCmd returns the `bf rules` subcommand.
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

// defaultConfigContent is the template written by `bf init`.
const defaultConfigContent = `# .bouncerfox.yml — BouncerFox scanner configuration
# Generated by: bf init

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

// newInitCmd returns the `bf init` subcommand.
func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Generate a default .bouncerfox.yml config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			const configFile = ".bouncerfox.yml"
			if _, err := os.Stat(configFile); err == nil {
				return fmt.Errorf("%s already exists; remove it first to regenerate", configFile)
			}
			if err := os.WriteFile(configFile, []byte(defaultConfigContent), 0644); err != nil {
				return fmt.Errorf("writing %s: %w", configFile, err)
			}
			fmt.Printf("Created %s\n", configFile)
			return nil
		},
	}
}
