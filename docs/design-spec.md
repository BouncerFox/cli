# Scanner Decoupling: Open Source Go CLI

**Date:** 2026-03-24
**Status:** Draft
**Author:** Human + Claude

## Problem

Users don't trust sending their code to a SaaS platform for scanning. Two user segments:
- **Type A:** Code must never leave their network
- **Type B:** Worried about data retention of secrets/credentials

Current architecture scans code server-side via Celery workers that fetch files from GitHub. This requires users to grant repo access and trust the platform with their code.

## Decision

Decouple the scanner from the platform into a standalone open source Go CLI. The scanner runs locally — code never leaves the user's machine. The governance platform remains closed source SaaS, monetized separately.

**Rationale:** Industry standard (Semgrep, Snyk, GitGuardian, Trivy) is to open source the scanner and monetize the platform. The scanner drives adoption; the platform is the moat. BouncerFox's value is in governance workflows (approvals, enforcement, compliance, audit trails), not the check functions.

## Architecture

### Two Products, Two Repos

```
bouncerfox/cli (open source, Go, Apache 2.0)
├── CLI tool
├── GitHub Action wrapper
├── Rules engine (28 built-in rules with check functions + 4 worker-generated rules)
├── Parser (SKILL.md, CLAUDE.md, settings.json, .mcp.json, agent.md)
├── Custom rule support (YAML-defined, 19 match primitives)
├── Config: .bouncerfox.yml
├── Output: table, JSON, SARIF, GitHub PR comments
└── Optional: upload findings to platform via API key

bouncerfox/bouncerfox (closed source, existing repo)
├── Governance platform (SaaS)
├── Approval workflows, enforcement modes
├── Custom rule builder UI (generates YAML served via API)
├── Rule profiles management
├── Compliance exports, audit trail
├── Team management, roles, billing
├── Catalog / skill registry
├── Cross-repo analytics
├── Notifications
└── Calls Go binary for server-side scanning (replaces Python scanner)
```

### Value Split

| Local scanner (open source) | SaaS platform (closed source) |
|---|---|
| Scan files, produce findings | Finding history, trends, dedup |
| Apply rule config from file | Rule config management UI |
| Output JSON/SARIF/table | Custom rule builder UI |
| Basic PR feedback (comments, check runs) | Approval workflows, enforcement |
| CLI / CI integration | Compliance exports, audit trail |
| Custom rules via YAML | Team management, roles, billing |
| | Catalog / skill registry |
| | Notifications |
| | Cross-repo analytics |

The scanner is valuable for individual repos. The platform is where organizational governance happens. One repo is linting. Fifty repos is governance.

## Go CLI Design

### Installation

```
brew install bouncerfox/tap/bouncerfox   # installs both 'bouncerfox' and 'bf'
curl -sSL https://get.bouncerfox.dev | sh
go install github.com/bouncerfox/cli@latest
```

### Commands

```
bf scan .                          # scan current dir, table output
bf scan . --format json            # JSON output
bf scan . --format sarif           # SARIF for IDE integration
bf scan . --config .bouncerfox.yml # custom config
bf scan . --github-comment         # post PR comment (needs GITHUB_TOKEN)
bf scan . --pr-number 42           # specify PR for comment (auto-detected in CI)
bf scan . --upload                 # upload findings to platform (needs API key)
bf scan . --dry-run-upload         # preview what would be sent
bf scan . --strip-paths            # send filenames only, not full paths
bf scan . --anonymous              # strip all identifying info (repo name, paths)
bf rules                           # list all rules
bf rules SEC_001                   # show rule detail
bf init                            # generate default .bouncerfox.yml
```

### Exit Codes

- `0` — no findings above threshold
- `1` — findings found above threshold
- `2` — scanner error

### Config File (.bouncerfox.yml)

```yaml
profile: recommended              # or "all_rules"
severity_threshold: warn          # fail CI on WARN and above
rules:
  SEC_001:
    enabled: true
    severity: critical            # override severity (floors enforced: CRITICAL rules >= HIGH)
  SEC_002:
    enabled: true
    params:
      url_allowlist:              # rule-specific parameters
        - "https://example.com"
  SEC_018:
    enabled: true
    params:
      min_entropy: 4.5            # entropy threshold
  QA_001:
    enabled: false
    file_types: [skill_md]        # narrow which file types this rule checks
ignore:
  - "vendor/**"
  - "*.test.md"
custom_rules:
  - id: CUSTOM_001
    name: No hardcoded model names
    category: cfg
    severity: warn
    file_types: [claude_md, settings_json]
    match:
      pattern: 'claude-3|gpt-4|gemini-pro'
      type: regex
    remediation: "Use model aliases instead of hardcoded model names"
```

CLI flags override config file values. Config file overrides profile defaults.

### Project Structure

```
scanner/
├── cmd/bouncerfox/main.go     # CLI entry point (cobra)
├── pkg/
│   ├── engine/                # scan orchestrator + suppression map + dedup
│   ├── rules/                 # rule registry + check functions
│   ├── parser/                # file type routing + parsing (goldmark for markdown AST)
│   ├── document/              # ConfigDocument type definition
│   ├── config/                # .bouncerfox.yml loading + validation
│   ├── custom/                # custom rule compiler (18 match primitives)
│   ├── fingerprint/           # content-stable SHA-256 fingerprints
│   ├── entropy/               # Shannon entropy + credential context detection
│   ├── output/                # formatters (table, json, sarif)
│   ├── github/                # PR comment, check run posting
│   └── upload/                # platform API client
├── .goreleaser.yml            # cross-platform release automation
├── action.yml                 # GitHub Action definition
└── Dockerfile                 # for Docker-based GitHub Action
```

### Key Design Decisions

- **Dual binary names:** `bouncerfox` (full) and `bf` (short) — both shipped in releases, no aliasing needed
- **Cobra** for CLI framework
- **GoReleaser** for automated cross-platform builds + Homebrew tap (produces both binary names)
- **No network calls by default** — fully offline unless `--github-comment` or `--upload`
- **Parallel file scanning** via goroutines
- **RE2 regex** (Go's `regexp` package) — guaranteed linear time, no ReDoS
- **goldmark** for markdown AST parsing (code block extraction, equivalent to Python's mistune)
- **SARIF output** — enables VS Code and GitHub Code Scanning integration

## Data Contracts

### ConfigDocument

Every file is parsed into a `ConfigDocument` before scanning. This is the contract between the parser and rule check functions.

```go
type ConfigDocument struct {
    FileType       string            // skill_md, claude_md, agent_md, settings_json, mcp_json
    FilePath       string            // relative path within scan root
    Content        string            // raw file content
    ContentHash    string            // SHA-256 of content
    Parsed         map[string]any    // structured data extracted by parser (see below)
}
```

**Parsed fields by file type:**

| File type | Parsed keys |
|---|---|
| skill_md | `name`, `description`, `version`, `author`, `tools`, `permissions`, `model`, `code_block_lines` (set of line numbers), all frontmatter fields |
| claude_md | `content_lines` (list of strings), `code_block_lines`, `has_frontmatter` |
| agent_md | Same as claude_md + `name`, `description` from frontmatter |
| settings_json | `json` (parsed JSON object), `keys` (all key paths), `permissions`, `mcpServers`, `hooks` |
| mcp_json | `json` (parsed JSON object), `servers` (server configs) |

**code_block_lines:** Set of 0-indexed line numbers within the file that are inside fenced code blocks. Most rules skip these lines (except SEC_001 which scans code blocks intentionally).

### JSON Output Schema (--format json)

```json
{
  "version": "1.0",
  "scanner_version": "0.1.0",
  "scan": {
    "timestamp": "2026-03-24T12:00:00Z",
    "duration_ms": 342,
    "root": "/path/to/repo",
    "total_files": 12,
    "scanned_files": 10,
    "profile": "recommended",
    "severity_threshold": "warn"
  },
  "findings": [
    {
      "rule_id": "SEC_001",
      "rule_name": "Hardcoded secret-like token",
      "category": "sec",
      "severity": "critical",
      "message": "Possible API key detected",
      "file_path": "SKILL.md",
      "line": 15,
      "evidence": {
        "key": "api_key",
        "context": "line_pattern_match"
      },
      "fingerprint": "a1b2c3d4...",
      "remediation": "Remove the secret and use environment variables"
    }
  ],
  "summary": {
    "critical": 1,
    "high": 0,
    "warn": 3,
    "info": 2,
    "total": 6
  }
}
```

**Evidence field:** Contains structured context about the match (key name, match type, field path) but NEVER contains the matched secret value itself (SEC_001 safety rule).

### Upload Payload Schema

Same as JSON output but with additional metadata and privacy controls applied:

```json
{
  "version": "1.0",
  "scanner_version": "0.1.0",
  "cli_version": "0.1.0",
  "repo": "org/repo-name",
  "commit_sha": "abc123",
  "scan": { ... },
  "findings": [ ... ]
}
```

When `--strip-paths` is used, `file_path` contains only the filename. When `--anonymous` is used, `repo` is omitted entirely.

## Scanner Engine Internals

### Suppression Map

When a specific rule fires on a file+line, generic rules are suppressed on that same location to avoid duplicate noise:

```
SEC_001 (pattern-based secret) suppresses → SEC_018 (entropy-based), SEC_006 (base64)
```

This is behavioral correctness, not optimization. The Go engine must implement the same suppression map from the Python `engine.py`.

### Severity Floors

CRITICAL rules cannot be downgraded below HIGH via config overrides. This is enforced at config resolution time, not in the engine. If a user sets `SEC_001: severity: info`, the effective severity is HIGH.

### Worker-Generated Rules

4 rules in the registry (SEC_019, SEC_020, QA_009, QA_010) have no check function — they are generated by the Celery worker layer (e.g., file-level checks like "file too large" or "file not found"). In the Go CLI, these become regular check functions since the CLI handles file I/O directly. They check file-level properties (size, existence) rather than content patterns.

### RE2 Compatibility

Go's `regexp` is RE2 (no lookaheads, no backreferences). **All 28 built-in check functions use Python's `re` (PCRE-compatible)** — only the custom rule compiler uses RE2. This means every rule's regex patterns need auditing during the port. During porting:
- Create a regex compatibility matrix as a first Phase 1 task (list every pattern, flag PCRE-only features)
- Rewrite lookahead patterns as two-pass checks (match, then verify context)
- Document each rewritten pattern in the rule's test file
- Verify parity via shared test fixtures

## Custom Rule DSL

The CLI supports the same 19 match primitives as the platform's custom rule compiler:

### Primitive Types

| Primitive | Description | Example |
|---|---|---|
| `line_pattern` | Regex match on individual lines | `pattern: 'TODO\|FIXME'` |
| `line_patterns` | Multiple regex patterns (all must match) | `patterns: ['import', 'os']` |
| `content_contains` | Substring match on full content | `value: 'eval('` |
| `content_not_contains` | Substring must NOT appear in content | `value: 'MIT License'` |
| `field_equals` | Parsed field exact match | `field: 'model', value: 'gpt-4'` |
| `field_exists` | Parsed field is present | `field: 'permissions'` |
| `field_missing` | Parsed field is absent | `field: 'description'` |
| `field_in` | Parsed field value in set | `field: 'model', values: [...]` |
| `field_not_in` | Parsed field value not in set | `field: 'model', values: [...]` |
| `field_matches` | Parsed field value matches regex | `field: 'name', pattern: '...'` |
| `collection_any` | Any item in collection matches | `field: 'tools', match: {...}` |
| `collection_none` | No item in collection matches | `field: 'tools', match: {...}` |
| `min_length` | Field value minimum length | `field: 'description', value: 50` |
| `max_length` | Field value maximum length | `field: 'name', value: 100` |
| `max_size_bytes` | File size limit | `value: 1048576` |
| `all_of` | All sub-matches must match (AND) | `matches: [...]` |
| `any_of` | Any sub-match must match (OR) | `matches: [...]` |
| `not` | Negation | `match: {...}` |
| `per_file_type` | Different match per file type | `file_types: {...}` |

Custom rule regex uses RE2 (same as built-in rules). No PCRE features.

## Platform Integration

### Upload Flow (opt-in)

```
bf scan . --upload --api-key bf_xxx
```

CLI scans locally, then sends only findings metadata to the platform. Code never leaves the machine.

**What gets sent:**

| Sent | Never sent |
|---|---|
| rule_id, severity, message | File contents |
| file_path, line number | Code snippets |
| fingerprint (hash) | Evidence values / matched strings |
| scan timestamp, duration | Environment variables |
| repo name (from git remote) | Secrets or credentials |
| commit SHA | Diff contents |

### Config Sync Flow (opt-in)

```
bf scan . --pull-config --api-key bf_xxx
```

Downloads org's rule config from platform, saves to `.bouncerfox.yml`.

### Platform API Endpoints (new)

- `POST /api/v1/scans/upload` — accepts findings from CLI
- `GET /api/v1/config/pull` — serves org rule config + custom rules as YAML
- New API key model — org-scoped, rotatable, separate from GitHub App credentials
- CLI uploads tagged with `trigger_type: CLI`

### API Key Scopes

Keys are scoped at creation time to limit blast radius if leaked:

| Scope | Grants |
|---|---|
| `scan:upload` | Upload findings to platform |
| `config:read` | Pull org rule config + custom rules |
| `scan:upload,config:read` | Both (default for convenience) |

Keys cannot access governance features (approvals, compliance, team management).

### Version Compatibility

The upload payload includes `cli_version` and schema `version`. The platform:
- Accepts findings with unknown `rule_id` values (stores them, displays as "custom/unknown")
- Ignores unknown fields in the payload (forward compatible)
- Returns `config_version` in pull-config responses; CLI warns if its version is older than the config requires
- Fingerprint algorithm is versioned — if it changes, the `version` field increments and the platform handles migration

### Platform Server-Side Scanning

The platform replaces its Python scanner with the Go binary:

```
Webhook → Celery task → fetch files to temp dir → bf scan /tmp/xyz --format json → parse JSON → store findings in DB
```

**Subprocess integration:**
- Go binary included in platform Docker image via multi-stage build (~10MB, compiled for target arch)
- Python wrapper function: `run_scanner(scan_dir, config_path) -> list[Finding]`
  - Calls subprocess with timeout (5 min SIGTERM, 5 min + 10s SIGKILL)
  - Parses JSON stdout; on non-zero exit, reads stderr for error message
  - Maps JSON findings to `Finding` DB model via schema validation
  - On binary crash/timeout: marks ScanRun as failed with error details
- Upgrading scanner = updating binary version in Dockerfile

**Server-side sandboxing:**
- Subprocess runs with minimal env vars (no DB credentials, no API keys passed through)
- Temp directory is cleaned up on success or failure (finally block)
- Memory limit via `resource.setrlimit` or container cgroup constraints
- Binary only has read access to the temp scan directory

## Security Model

### Threat 1: Malicious config files
- YAML parsing with Go's `yaml.v3` strict mode — no arbitrary type deserialization
- Config schema validation — reject unknown fields
- Custom rule regex via Go's `regexp` (RE2) — guaranteed linear time, no ReDoS

### Threat 2: Path traversal
- Resolve all file paths to absolute, verify within scan root
- Reject symlinks pointing outside scan root
- Ignore `.git/` directory contents

### Threat 3: Resource exhaustion
- Max file size: 1MB per file
- Max file count: 500 per scan
- Scan timeout: 5 minutes total, 30s per file
- Memory cap on regex matches per file

### Threat 4: API key leakage
- Accepted via `--api-key` flag, `BOUNCERFOX_API_KEY` env var, or config file
- Warn if API key is in `.bouncerfox.yml` and not in `.gitignore`
- Never logged or printed in output
- HTTPS only — reject HTTP, no `--insecure` flag

### Threat 5: Supply chain (compromised binary)
- GoReleaser produces signed binaries with checksums
- SLSA provenance attestation via `actions/attest-build-provenance`
- Users verify with `gh attestation verify`
- Homebrew formula pins to checksums
- Builds are reproducible from source

### Threat 6: GitHub token abuse
- Only calls create/update check run and create/update comment endpoints
- Token never sent to platform, never logged
- Validate token scopes, warn if overly permissive

### Threat 7: Upload tampering
- TLS required, certificate validation enforced
- API key via `Authorization` header, not query params
- Request signing with timestamp to prevent replay attacks
- Platform validates findings schema strictly

### Threat 8: Findings data sensitivity
- `--upload` is opt-in, never default
- `--dry-run-upload` to preview what would be sent
- `--strip-paths` sends only filenames, not full paths
- `--anonymous` strips all identifying info (repo name, paths)

### Threat 9: Server-side binary exploitation
When the platform calls the Go binary with untrusted repo content:
- Subprocess runs with minimal environment (no DB credentials leaked)
- Subprocess timeout with SIGKILL fallback
- Temp directory cleanup in finally block
- Memory limits via cgroup/rlimit
- Binary has read-only access to scan directory

## Migration & Rollout

### Phase 1: Build the Go CLI (new repo)
- Port parser (using goldmark for markdown AST), engine, 32 rules, fingerprinting, entropy detection
- Port suppression map and severity floor logic
- Port custom rule compiler (19 match primitives)
- Implement config loading, output formatters (table, JSON, SARIF)
- Implement GitHub PR feedback (--github-comment)
- Test against shared fixtures derived from current Python tests
- Verify RE2 parity for all regex patterns
- Release v0.1.0, open source under Apache 2.0

### Phase 2: GitHub Action + CI integrations
- Docker-based GitHub Action calling the CLI
- GitHub Marketplace listing
- Docs + examples for GitLab CI, Bitbucket Pipelines, Jenkins

### Phase 3: Platform integration
- Add `--upload` and `--pull-config` to CLI
- New platform API endpoints (upload, pull-config, API key management)
- Build Python subprocess wrapper for server-side scanning
- Run both Python and Go scanners in parallel, compare results (parity validation period)
- When parity confirmed, switch to Go binary as primary

### Phase 4: Remove Python scanner
- Remove `backend/app/scanner/`, `backend/app/parser/`, related tests
- Update platform tests to use Go binary via subprocess wrapper
- Remove Python scanner dependencies from requirements

## Open Questions

- **Telemetry:** Should the CLI collect anonymous usage stats (opt-in)? Common in open source CLIs.
- **Auto-fix:** Should we plan for `--fix` support (like Semgrep)? Not v0.1, but affects architecture if planned.
- **`bf init` behavior:** Interactive wizard or just write a default file? Start with default file, iterate based on feedback.
