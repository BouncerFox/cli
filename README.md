# BouncerFox CLI

Scan AI agent config files for security, quality, and compliance issues.
Code never leaves your machine. The scanner runs entirely offline.

![BouncerFox CLI Demo](demo/demo.gif)

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

### Build from Source

Requires Go 1.25+.

```bash
# Clone and build
git clone https://github.com/bouncerfox/cli.git
cd cli
go build -o bouncerfox ./cmd/bouncerfox

# Or install directly into $GOPATH/bin
go install ./cmd/bouncerfox

# Build with version tag
go build -ldflags "-X main.version=v0.6.0" -o bouncerfox ./cmd/bouncerfox

# Run tests
go test ./... -race
```

## Quick Start

```bash
# Scan the current directory
bouncerfox scan .

# Only show high-severity and above
bouncerfox scan . --severity high

# Group by severity (great for triage and demos)
bouncerfox scan . --group-by severity

# Group by rule (fix all instances of one problem)
bouncerfox scan . --group-by rule

# Show remediation and code context
bouncerfox scan . -v

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
| `2` | Scanner error |

Release builds currently run in offline mode. The platform verdict contract is implemented
and tested for the forthcoming connected mode, but it is not enabled in release binaries.

## Rules

35 built-in rules across four categories:

| Category | Prefix | Count | Focus |
|---|---|---|---|
| Security | `SEC_` | 16 | Hardcoded secrets, dangerous commands, supply chain, exfiltration |
| Quality | `QA_` | 10 | Missing fields, thin descriptions, oversized files, binary detection |
| Config | `CFG_` | 8 | Overly broad permissions, hook injection, hook review, MCP misconfig |
| Prompt Safety | `PS_` | 1 | Hidden HTML comments with embedded instructions |

Example rule IDs: `SEC_001` (hardcoded secret), `SEC_018` (high-entropy string),
`CFG_001` (unrestricted Bash), `QA_001` (missing description), `PS_004` (hidden HTML comment), `SEC_021` (dangerous import reference).

Run `bouncerfox rules` for the full list with severities and descriptions.

## Configuration

BouncerFox loads config from two locations, merged together:

| Scope | Location | Purpose |
|-------|----------|---------|
| Global | `~/.config/bouncerfox/config.yml` | User-wide defaults (ignore patterns, allowlists, rule overrides) |
| Project | `.bouncerfox.yml` | Project-specific settings (committed to repo) |

Override the global config directory with `BOUNCERFOX_CONFIG_DIR`.
When `--config` is provided, only that file is used (global config is skipped).

### Config Layering

When both global and project configs exist, they are merged:

- **Scalars** (`profile`, `severity_floor`): project wins if set, otherwise global
- **Lists** (`ignore`): combined from both (additive, deduplicated)
- **Rules**: deep-merged per rule ID. Project overrides specific fields, unset fields inherit from global.
- **Rule params**: replaced wholesale. Project params for a rule replace global params entirely.
- **CLI flags**: always override both config files
- **Platform config**: reserved for connected mode; release builds do not fetch it

Example. Global config sets org-wide defaults:

```yaml
# ~/.config/bouncerfox/config.yml
ignore:
  - "plugins/marketplaces/**"
rules:
  SEC_002:
    params:
      url_allowlist:
        - "https://internal.corp.com"
```

Project config adds project-specific settings:

```yaml
# .bouncerfox.yml
profile: recommended
severity_floor: warn
ignore:
  - "vendor/**"
rules:
  SEC_002:
    severity: warn
```

Merged result: both ignore patterns apply, SEC_002 gets `warn` severity from project and `url_allowlist` from global.

### Config Options

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
    file_types: [skill_md, claude_md]  # narrow which file types this rule checks
  SEC_018:
    enabled: true
    params:
      base64_threshold_freetext: 4.5  # per-charset entropy thresholds
  QA_001:
    enabled: false            # disable a rule entirely
```

CLI flags override config file values. Config file overrides profile defaults.

**Profiles:** `recommended` (default) disables some informational rules for a quieter baseline.
`all_rules` enables every rule. Per-rule overrides in `rules:` are applied on top of the profile.

**Severity floors:** Critical rules (`SEC_001`, `SEC_003`, `SEC_004`) cannot be downgraded below HIGH.
Floor rules also ignore `file_types` overrides.

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
      - uses: bouncerfox/cli@v0
        with:
          path: .
          format: sarif
          severity: warn
```

### SARIF upload to GitHub Code Scanning

The CLI writes SARIF to standard output, so save it before invoking GitHub's uploader:

```yaml
      - name: Run BouncerFox
        run: bouncerfox scan . --format sarif > results.sarif || test "$?" -eq 1
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

### Connected mode status

Connected mode is under integration and is deliberately disabled in release builds.
Setting `BOUNCERFOX_API_KEY` currently prints a note and the scan continues offline;
it does not fetch platform config, upload findings, or use a remote verdict.

The config-pull, upload, privacy, caching, and verdict contracts remain covered by the
CLI test suite while platform policy resolution and end-to-end release validation are
completed. Do not depend on connected-mode flags or API-key authentication in production
automation yet.

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
| `--offline-behavior` | | | Pre-release connected mode: upload failure behavior (`warn` or `fail-closed`) |
| `--dry-run-upload` | | `false` | Preview upload payload without sending |
| `--strip-paths` | | `false` | Send filenames only (no full paths) in upload |
| `--anonymous` | | `false` | Preview an upload without target, commit, or branch fields; full connected-mode privacy is not released |
| `--no-cache` | | `false` | Pre-release connected mode: skip platform config cache |
| `--group-by` | | `file` | Group findings by: `file`, `rule`, `severity` |
| `--verbose` | `-v` | `false` | Show remediation and code frames |
| `--ignore` | | | Gitignore-style globs to skip (repeatable) |
| `--no-color` | | `false` | Disable colors and Unicode symbols |

### `bouncerfox rules`

List all registered rules with ID, severity, category, and description.

### `bouncerfox init`

Generate a default `.bouncerfox.yml` in the current directory. Fails if one already exists.

### `bouncerfox version`

Print the scanner version.

### `bouncerfox completion [bash|zsh|fish|powershell]`

Generate a shell completion script for the specified shell.

### `bouncerfox auth`

Reserved for platform authentication. Release builds currently report that the platform
integration is coming soon and do not open a browser or store credentials.

### `bouncerfox config refresh`

Clear the cached platform config. Useful when org-level rules have changed and you want
to pull fresh config on the next scan.

## Environment Variables

| Variable | Description |
|---|---|
| `BOUNCERFOX_API_KEY` | Reserved platform API key. Release builds remain offline when it is set. |
| `BOUNCERFOX_PLATFORM_URL` | Reserved platform API base URL (default: `https://api.bouncerfox.dev`) |
| `BOUNCERFOX_CONFIG_DIR` | Config directory override (default: `~/.config/bouncerfox`) |
| `BOUNCERFOX_TARGET` | Override scan target identity |
| `GITHUB_TOKEN` | Required for `--github-comment` (PR comments and check runs) |
| `NO_COLOR` | Disable colors and Unicode symbols in table output (any value) |

CI environment variables (`GITHUB_ACTIONS`, `CI`, `GITHUB_SHA`, `GITHUB_REF_NAME`,
`GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH`) are auto-detected when running in GitHub Actions.

## Platform Integration

The BouncerFox platform is intended to add approval flows, enforcement policies,
compliance exports, and cross-project analytics on top of the offline scanner. The
wire contracts and integration code are present for development, but connected mode
will remain disabled until the CLI and a running platform pass the release integration
matrix with one shared governance policy.

`--dry-run-upload` can be used to inspect the proposed upload payload without sending it.
The contract is designed to send rule IDs, severities, paths, line numbers, fingerprints,
and scan metadata—not file contents, code snippets, matched secret values, or environment
variables.

## Security

- **Offline release builds.** Setting `BOUNCERFOX_API_KEY` does not enable network access; `--github-comment` is the explicit networked scan path.
- Max file size: 1 MB. Max file count: 500. Scan timeout: 5 minutes.
- Symlinks pointing outside the scan root are rejected
- Custom rule regex uses RE2. No ReDoS risk.
- Signed binaries with SLSA provenance attestation. Verify with `gh attestation verify`.

## Shell Completions

Generate tab-completion scripts for your shell:

```bash
# Bash: add to ~/.bashrc
eval "$(bouncerfox completion bash)"

# Zsh: add to ~/.zshrc (or place in $fpath)
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

Apache 2.0. See [LICENSE](LICENSE).

Copyright 2026 BouncerFox Contributors.
