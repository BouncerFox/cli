# BouncerFox CLI

Scan AI agent config files for security, quality, and compliance issues.
Code never leaves your machine — the scanner runs entirely offline.

## What It Scans

| File | Description |
|---|---|
| `SKILL.md` | Skill definitions with YAML frontmatter |
| `CLAUDE.md` | Claude context files |
| `CLAUDE.local.md` | Local Claude context files |
| `.claude/agents/*.md` | Agent definitions |
| `.claude/commands/*.md` | Legacy command definitions |
| `.claude/settings*.json` | Claude settings (permissions, hooks, MCP) |
| `.claude/rules/**/*.md` | Modular rules with optional paths frontmatter |
| `.claude-plugin/plugin.json` | Plugin manifests |
| `hooks/hooks.json` | Plugin hook configuration |
| `.mcp.json` | MCP server configuration |
| `.lsp.json` | LSP server configuration |
| `.cursorrules` | Cursor AI instructions |
| `.windsurfrules` | Windsurf AI instructions |
| `.github/copilot-instructions.md` | GitHub Copilot instructions |
| `AGENTS.md` | Gemini agent definitions |

## Installation

```bash
# Homebrew (macOS / Linux)
brew tap bouncerfox/tap
brew install --cask bouncerfox

# Go toolchain
go install github.com/bouncerfox/cli/cmd/bouncerfox@latest
```

Releases also ship standalone binaries for Linux, macOS, and Windows via
[GitHub Releases](https://github.com/bouncerfox/cli/releases).

## Quick Start

```bash
# Scan the current directory
bouncerfox scan .

# Only show high-severity and above
bouncerfox scan . --severity high

# JSON output (pipe to jq, CI scripts)
bouncerfox scan . --format json

# SARIF output (VS Code / GitHub Code Scanning)
bouncerfox scan . --format sarif

# List all built-in rules
bouncerfox rules

# Generate a starter .bouncerfox.yml
bouncerfox init
```

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above the severity threshold |
| `1` | One or more findings found |
| `2` | Scanner error (or platform unreachable in fail-closed mode) |

## Rules

34 built-in rules across four categories:

| Category | Prefix | Count | Focus |
|---|---|---|---|
| Security | `SEC_` | 16 | Hardcoded secrets, dangerous commands, supply chain, exfiltration |
| Quality | `QA_` | 10 | Missing fields, thin descriptions, oversized files, binary detection |
| Config | `CFG_` | 7 | Overly broad permissions, hook injection, MCP misconfig |
| Prompt Safety | `PS_` | 1 | Hidden HTML comments with embedded instructions |

Example rule IDs: `SEC_001` (hardcoded secret), `SEC_018` (high-entropy string),
`CFG_001` (unrestricted Bash), `QA_001` (missing description), `PS_004` (hidden HTML comment), `SEC_021` (dangerous import reference).

Run `bouncerfox rules` for the full list with severities and descriptions.

## Config (`.bouncerfox.yml`)

```yaml
# profile: "recommended" (default) or "all_rules"
profile: recommended

# severity_floor: minimum severity to report (info, warn, high, critical)
severity_floor: warn

# ignore: gitignore-style globs to skip
ignore:
  - "vendor/**"
  - "**/*.generated.md"

# rules: per-rule overrides
rules:
  SEC_001:
    enabled: true
    severity: critical        # severity override (floors enforced: CRITICAL >= HIGH)
  SEC_002:
    enabled: true
    params:
      url_allowlist:
        - "https://api.example.com"
  SEC_018:
    enabled: true
    params:
      min_entropy: 4.5        # entropy threshold for SEC_018
  QA_001:
    enabled: false            # disable a rule entirely
  SEC_002:
    file_types: [skill_md, claude_md]  # narrow which file types this rule checks
```

CLI flags override config file values. Config file overrides profile defaults.

**Profiles:** `recommended` (default) disables some informational rules for a quieter baseline.
`all_rules` enables every rule. Per-rule overrides in `rules:` are applied on top of the profile.

**Severity floors:** Critical rules (`SEC_001`, `SEC_003`, `SEC_004`) cannot be downgraded below HIGH.

## Custom Rules

Define project-specific rules in `.bouncerfox.yml` without writing Go:

```yaml
custom_rules:
  - id: CUSTOM_001
    name: No hardcoded model names
    category: cfg
    severity: warn
    file_types: [claude_md, settings_json]
    match:
      type: line_pattern
      pattern: 'claude-3\.[a-z]|gpt-4|gemini-pro'
    remediation: "Use model aliases instead of hardcoded model names"

  - id: CUSTOM_002
    name: Description must be substantive
    category: qa
    severity: warn
    file_types: [skill_md]
    match:
      type: min_length
      field: description
      value: 50
    remediation: "Write a description of at least 50 characters"
```

19 match primitives are available: `line_pattern`, `line_patterns`, `content_contains`,
`content_not_contains`, `field_equals`, `field_exists`, `field_missing`, `field_in`,
`field_not_in`, `field_matches`, `collection_any`, `collection_none`, `min_length`,
`max_length`, `max_size_bytes`, `all_of`, `any_of`, `not`, `per_file_type`.

All custom rule patterns use RE2 regex (no lookaheads or backreferences).

## CI / GitHub Actions

### Basic scan

```yaml
# .github/workflows/bouncerfox.yml
name: BouncerFox Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bouncerfox/cli@v1
        with:
          path: .
          format: sarif
          severity: warn
```

### SARIF upload to GitHub Code Scanning

```yaml
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### PR comments and check runs

Post findings directly on a pull request and as a GitHub check run with inline annotations:

```yaml
    steps:
      - uses: actions/checkout@v4
      - run: |
          bouncerfox scan . --github-comment --pr-number ${{ github.event.pull_request.number }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

`--github-comment` requires the `GITHUB_TOKEN` environment variable. The PR number is
auto-detected from the GitHub event payload when `--pr-number` is not set. If a commit SHA
is available, a check run with per-file annotations is also posted.

### Connected mode (platform integration)

When `BOUNCERFOX_API_KEY` is set, the CLI automatically enters connected mode:
pulls org-level rule config before scanning, uploads findings after, and uses the
platform's verdict for the exit code.

```yaml
    steps:
      - uses: actions/checkout@v4
      - run: bouncerfox scan .
        env:
          BOUNCERFOX_API_KEY: ${{ secrets.BOUNCERFOX_API_KEY }}
```

If the platform is unreachable in CI, the default behavior is **fail-closed** (exit 2).
Override with `--offline-behavior warn` to fall back to local exit logic.

## CLI Reference

### `bouncerfox scan [paths...]`

Scan files for security and quality issues. Defaults to scanning the current directory.

| Flag | Short | Default | Description |
|---|---|---|---|
| `--format` | `-f` | `table` | Output format: `table`, `json`, `sarif` |
| `--severity` | `-s` | | Severity floor: `critical`, `high`, `warn`, `info` |
| `--config` | `-c` | | Config file path (overrides auto-discovery) |
| `--max-findings` | | `0` | Cap total findings (0 = unlimited) |
| `--github-comment` | | `false` | Post findings as PR comment and check run |
| `--pr-number` | | `0` | PR number for GitHub comment (auto-detected in CI) |
| `--target` | | | Override scan target identity |
| `--trigger` | | | Override trigger detection: `ci` or `local` |
| `--offline-behavior` | | | When upload fails: `warn` or `fail-closed` (auto: fail-closed in CI, warn locally) |
| `--dry-run-upload` | | `false` | Preview upload payload without sending |
| `--strip-paths` | | `false` | Send filenames only (no full paths) in upload |
| `--anonymous` | | `false` | Strip all identifying info from upload |
| `--no-cache` | | `false` | Skip config cache (always pull fresh) |

### `bouncerfox rules`

List all registered rules with ID, severity, category, and description.

### `bouncerfox init`

Generate a default `.bouncerfox.yml` in the current directory. Fails if one already exists.

### `bouncerfox version`

Print the scanner version.

### `bouncerfox completion [bash|zsh|fish|powershell]`

Generate a shell completion script for the specified shell.

### `bouncerfox auth`

Authenticate with the BouncerFox platform. Opens a browser to obtain an API key and
saves it to `~/.config/bouncerfox/credentials`.

### `bouncerfox config refresh`

Clear the cached platform config. Useful when org-level rules have changed and you want
to pull fresh config on the next scan.

## Environment Variables

| Variable | Description |
|---|---|
| `BOUNCERFOX_API_KEY` | Platform API key — enables connected mode (config pull + upload + verdict) |
| `BOUNCERFOX_PLATFORM_URL` | Platform API base URL (default: `https://api.bouncerfox.dev`) |
| `BOUNCERFOX_CONFIG_DIR` | Config directory override (default: `~/.config/bouncerfox`) |
| `BOUNCERFOX_TARGET` | Override scan target identity |
| `GITHUB_TOKEN` | Required for `--github-comment` (PR comments and check runs) |

CI environment variables (`GITHUB_ACTIONS`, `CI`, `GITHUB_SHA`, `GITHUB_REF_NAME`,
`GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH`) are auto-detected when running in GitHub Actions.

## Platform Integration

The BouncerFox platform adds governance workflows on top of the CLI scanner:
approval flows, enforcement policies, compliance exports, and cross-repo analytics.

**Connected mode** activates automatically when `BOUNCERFOX_API_KEY` is set (via env var
or `bouncerfox auth`). In connected mode the CLI:

1. Pulls org-level rule config from the platform (cached locally with ETag validation)
2. Runs the scan with merged config (platform config takes priority over local)
3. Uploads findings to the platform
4. Uses the platform's verdict for the exit code

**What gets sent:** rule IDs, severities, file paths, line numbers, fingerprints, scan metadata.
**Never sent:** file contents, code snippets, matched secret values, environment variables.

```bash
# Authenticate (saves API key locally)
bouncerfox auth

# Scan — connected mode activates automatically
bouncerfox scan .

# Preview what would be uploaded
bouncerfox scan . --dry-run-upload

# Strip full paths from upload payload
bouncerfox scan . --strip-paths

# Fully anonymous upload (no target, commit, or branch info)
bouncerfox scan . --anonymous

# Force fresh config pull (skip cache)
bouncerfox scan . --no-cache

# Clear cached config
bouncerfox config refresh
```

Set the API key via environment variable to avoid it appearing in shell history:

```bash
export BOUNCERFOX_API_KEY=bf_xxx
bouncerfox scan .
```

## Security

- **Offline by default** — no network calls unless `BOUNCERFOX_API_KEY` is set or `--github-comment` is used
- Max file size: 1 MB; max file count: 500; scan timeout: 5 minutes
- Symlinks pointing outside the scan root are rejected
- Custom rule regex uses RE2 — no ReDoS risk
- Signed binaries with SLSA provenance attestation; verify with `gh attestation verify`

## Shell Completions

Generate tab-completion scripts for your shell:

```bash
# Bash — add to ~/.bashrc
eval "$(bouncerfox completion bash)"

# Zsh — add to ~/.zshrc (or place in $fpath)
bouncerfox completion zsh > "${fpath[1]}/_bouncerfox"

# Fish
bouncerfox completion fish | source
```

Example:

```
$ bouncerfox sc<TAB>
scan

$ bouncerfox scan --fo<TAB>
--format

$ bouncerfox completion <TAB>
bash  fish  powershell  zsh
```

## License

Apache 2.0 — see [LICENSE](LICENSE).

Copyright 2026 BouncerFox Contributors.
