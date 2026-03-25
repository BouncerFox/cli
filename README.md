# BouncerFox CLI

Scan AI agent config files for security, quality, and compliance issues.
Code never leaves your machine — the scanner runs entirely offline.

## What It Scans

| File | Description |
|---|---|
| `SKILL.md` | Skill definitions with YAML frontmatter |
| `CLAUDE.md` | Claude context files |
| `.claude/agents/*.md` | Agent definitions |
| `.claude/settings*.json` | Claude settings (permissions, hooks, MCP) |
| `.mcp.json` | MCP server configuration |

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
# Scan the current directory (table output)
bouncerfox scan .

# JSON output (machine-readable, pipe to jq)
bouncerfox scan . --format json

# SARIF output (VS Code / GitHub Code Scanning)
bouncerfox scan . --format sarif

# List all rules
bouncerfox rules

# Generate a default .bouncerfox.yml
bouncerfox init
```

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above the severity threshold |
| `1` | One or more findings found |
| `2` | Scanner error |

## Rules

33 built-in rules across four categories:

| Category | Prefix | Count | Focus |
|---|---|---|---|
| Security | `SEC_` | 15 | Hardcoded secrets, dangerous commands, supply chain, exfiltration |
| Quality | `QA_` | 10 | Missing fields, thin descriptions, oversized files, binary detection |
| Config | `CFG_` | 7 | Overly broad permissions, hook injection, MCP misconfig |
| Prompt Safety | `PS_` | 1 | Hidden HTML comments with embedded instructions |

Example rule IDs: `SEC_001` (hardcoded secret), `SEC_018` (high-entropy string),
`CFG_001` (unrestricted Bash), `QA_001` (missing description), `PS_004` (hidden HTML comment).

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
    file_types: [skill_md]    # narrow which file types this rule checks
```

CLI flags override config file values. Config file overrides profile defaults.

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

## GitHub Action

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

For SARIF upload to GitHub Code Scanning, add:

```yaml
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## CLI Flags

### `bouncerfox scan [paths...]`

| Flag | Short | Default | Description |
|---|---|---|---|
| `--format` | `-f` | `table` | Output format: `table`, `json`, `sarif` |
| `--severity` | `-s` | `` | Severity floor override: `critical`, `high`, `warn`, `info` |
| `--config` | `-c` | `` | Config file path (overrides auto-discovery) |
| `--max-findings` | | `0` | Cap total findings returned (0 = unlimited) |

### `bouncerfox rules`

Lists all registered rules with ID, severity, category, and description.

### `bouncerfox init`

Writes a default `.bouncerfox.yml` to the current directory.

## Platform Integration (optional)

The BouncerFox platform adds governance workflows on top of the CLI scanner:
approval flows, enforcement policies, compliance exports, and cross-repo analytics.

```bash
# Upload findings to the platform (opt-in)
bouncerfox scan . --upload --api-key bf_xxx

# Download org rule config from the platform
bouncerfox scan . --pull-config --api-key bf_xxx
```

What gets sent with `--upload`: rule IDs, severities, file paths, line numbers,
fingerprints, scan metadata. What is **never** sent: file contents, code snippets,
matched secret values, environment variables.

Set the API key via environment variable to avoid it appearing in shell history:

```bash
export BOUNCERFOX_API_KEY=bf_xxx
bouncerfox scan . --upload
```

## Security Notes

- No network calls by default — fully offline unless `--upload` or `--pull-config` is used
- Max file size: 1 MB per file; max file count: 500 per scan; scan timeout: 5 minutes
- Symlinks pointing outside the scan root are rejected
- Custom rule regex uses RE2 — no ReDoS risk
- Signed binaries with SLSA provenance attestation; verify with `gh attestation verify`

## License

Apache 2.0 — see [LICENSE](LICENSE).

Copyright 2026 BouncerFox Contributors.
