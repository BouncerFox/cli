# CLAUDE.md

## Project Overview

BouncerFox CLI (`bf`) — an open source Go CLI that scans AI agent config files for security, quality, and compliance issues. This is the scanner component of the BouncerFox governance platform.

**Repo:** github.com/bouncerfox/cli
**License:** Apache 2.0
**Language:** Go 1.24+

## What This Scans

AI agent configuration files:
- `SKILL.md` — skill definitions with YAML frontmatter
- `CLAUDE.md` — Claude context files
- `.claude/agents/*.md` — agent definitions
- `.claude/settings*.json` — Claude settings
- `.mcp.json` — MCP server configuration

## Key Documents

- `docs/plan.md` — Full implementation plan (19 tasks, step-by-step)
- `docs/design-spec.md` — Architecture design spec

## Python Source Reference

This is a Go port of the Python scanner from the BouncerFox platform repo (`/home/mr47/workspace/skillplane`). Key Python source files:

- `backend/app/scanner/engine.py` — scan orchestrator, suppression map
- `backend/app/scanner/rules.py` — rule registry (32 rules)
- `backend/app/scanner/checks/sec.py` — security rules
- `backend/app/scanner/checks/qa.py` — quality rules
- `backend/app/scanner/checks/cfg.py` — config rules
- `backend/app/scanner/checks/ps.py` — prompt safety rules
- `backend/app/scanner/entropy.py` — entropy detection
- `backend/app/scanner/fingerprint.py` — finding fingerprints
- `backend/app/scanner/custom_compiler.py` — custom rule compiler (19 match primitives)
- `backend/app/scanner/rule_config.py` — config resolution, severity floors
- `backend/app/scanner/_patterns.py` — shared regex patterns
- `backend/app/scanner/_helpers.py` — shared helpers
- `backend/app/scanner/_params.py` — default rule parameters
- `backend/app/parser/` — file parsers and routing

When porting a rule, always read the Python source to get exact regex patterns and logic.

## Commands

```bash
go test ./... -v              # run all tests
go test ./pkg/document/ -v    # run specific package tests
go build -o bf ./cmd/bouncerfox  # build binary
./bf scan .                   # run scanner
./bf rules                    # list rules
./bf init                     # generate config
```

## Architecture

```
cmd/bouncerfox/main.go        # CLI entry point (Cobra)
pkg/
  document/                    # Core types (ConfigDocument, ScanFinding, FindingSeverity)
  parser/                      # File parsers + routing
  rules/                       # Rule registry + check functions + helpers
  engine/                      # Scan orchestrator
  entropy/                     # Shannon entropy detection
  fingerprint/                 # Content-stable fingerprints
  custom/                      # Custom rule compiler
  config/                      # .bouncerfox.yml loading
  output/                      # Formatters (table, JSON, SARIF)
  github/                      # PR feedback (check runs, comments)
  upload/                      # Platform API client
```

## Conventions

- TDD: write failing test, implement, verify
- One commit per task
- Go standard project layout
- `go test ./... -race` must pass
- Follow the plan in `docs/plan.md` task by task

## Critical Implementation Notes

- **Rule execution order matters:** SEC_001 must run before SEC_006/SEC_018 (caches line numbers). Use ordered slice, not map iteration.
- **Two code block line sets:** `code_block_lines` (body-relative) vs `content_code_block_lines` (full-file-relative). Rules must use the correct one.
- **SEC_001 never stores secret values:** evidence.snippet is always `""`.
- **RE2 regex only:** Go's `regexp` is RE2. No lookaheads or backreferences. Check `docs/re2-audit.md` (Task 2) for rewrite strategies.
- **Severity floors:** CRITICAL rules cannot be downgraded below HIGH.
- **ApplyResolvedOverrides:** Post-scan filtering that makes per-rule params work. Without it, config params are loaded but never applied.
