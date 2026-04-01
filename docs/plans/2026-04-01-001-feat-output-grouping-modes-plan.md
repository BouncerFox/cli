---
title: "feat: Add output grouping modes and polish"
type: feat
status: active
date: 2026-04-01
origin: docs/brainstorms/2026-04-01-cli-output-polish-requirements.md
---

# feat: Add output grouping modes and polish

## Overview

Add `--group-by=file|rule|severity` flag to the table formatter. File remains the default. Rule and severity modes provide alternative views for demos, triage, and fixing all instances of one rule. Also move remediation behind `--verbose` and add severity-colored summary counts.

## Problem Frame

The CLI currently only groups findings by file. For demos and security triage, grouping by severity (critical first) or by rule (fix one problem type at a time) is more useful. The output also needs polish: remediation text clutters default output, and severity counts in the summary banner lack color coding. (see origin: docs/brainstorms/2026-04-01-cli-output-polish-requirements.md)

## Requirements Trace

- R1. `--group-by` flag accepting `file` (default), `rule`, `severity`
- R2. Group-by-file remains the default
- R3. Group-by-severity: CRITICAL > HIGH > WARN > INFO, sub-sorted by file path then line
- R4. Group-by-rule: sorted by severity tier then rule ID alphanumerically, headers show rule ID + name
- R5. Bold group label with finding count appended, e.g., `"SEC_001 Hardcoded Secret (3 findings)"`
- R6. Remediation behind `--verbose` only (intentional breaking change)
- R7. Summary banner at bottom with severity-colored counts in TTY
- R8. Consistent column alignment across all grouping modes

## Scope Boundaries

- `--group-by` only affects table format. JSON and SARIF are unchanged.
- No inline suppression hints (attack vector for untrusted scanned content).
- No `--fail-on` flag (existing `--severity` covers this).
- No `--compact` mode, no baseline/diff mode, no progress indicators.

## Context & Research

### Relevant Code and Patterns

- `pkg/output/table.go` - Current `FormatTable` with file grouping, summary banner, `FormatOptions` struct
- `pkg/output/display.go` - `renderMode` struct, `severityBadge()`, `bold()`, `color()`, ANSI constants
- `pkg/output/verbose.go` - `writeCodeFrame()` for `--verbose` mode
- `pkg/output/table_test.go` - Internal tests using `bytes.Buffer` and `strings.Contains` assertions
- `pkg/document/document.go` - `ScanFinding` (has `RuleID`, no `Name`), `RuleMetadata` (has `Name`)
- `pkg/rules/registry.go` - `Registry []document.RuleMetadata`, accessed from `cmd/bouncerfox/main.go`
- `cmd/bouncerfox/main.go:538-554` - Cobra flag definitions, format switch at lines 354-379

### Institutional Learnings

No `docs/solutions/` exists. No prior art to consider.

## Key Technical Decisions

- **Pass rule names via FormatOptions, not by importing rules package:** The output package is intentionally decoupled from the rules package. Adding `RuleNames map[string]string` to `FormatOptions` keeps this boundary clean. The map is built in `main.go` from both `rules.Registry` and any loaded custom rules, and populated when `--group-by=rule`.
- **Generalize grouping by changing the group key:** The existing group/entry pattern in `FormatTable` generalizes naturally. The group key changes based on mode (file path, rule ID, severity string), and the header rendering changes per mode. The summary banner is independent and stays unchanged.
- **Severity color in summary uses existing renderMode helpers:** `rm.color()` with the existing ANSI constants (`ansiRedBold`, `ansiRed`, `ansiYellow`, `ansiCyan`) maps directly to severity levels. No new color infrastructure needed.

## Open Questions

### Resolved During Planning

- **Are rule names available?** Yes. `RuleMetadata.Name` in `pkg/document/document.go:73`. Available via `rules.Registry` in main.go.
- **Header format for groups?** Use `rm.bold()` for the group label with finding count appended in parentheses, e.g., `"SEC_001 Hardcoded Secret (3 findings)"`. No thin rule lines and no right-alignment. Keep it simple and consistent with existing bold-text file headers.
- **Severity sorting for group-by-rule:** Uses the effective severity from findings (post-config-resolution), not `RuleMetadata.DefaultSeverity`. This is correct since config overrides are intentional. All findings for a given rule ID share the same effective severity after resolution, so using the highest severity among a rule's findings handles any edge cases.
- **Does remediation change affect code frames?** No. Code frames (`writeCodeFrame`) are already gated on `opts.Verbose`. Remediation just needs the same gate.

### Deferred to Implementation

- Exact column widths for the file:line field in rule/severity modes may need tuning based on real output.

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
FormatOptions gains:
  GroupBy    string              // "file" | "rule" | "severity"
  RuleNames map[string]string   // ruleID -> human name (populated only for group-by-rule)

FormatTable flow:
  1. Build groups based on GroupBy mode
     - "file":     key = relative file path (current behavior)
     - "rule":     key = ruleID
     - "severity": key = severity string
  2. Sort groups based on mode
     - "file":     alphabetical by file path
     - "rule":     by highest effective severity among findings, then alphanumeric by rule ID
     - "severity": fixed order CRITICAL > HIGH > WARN > INFO
  3. Render each group
     - Header: group label (bold) + finding count appended in parens
       - "file":     file path
       - "rule":     "SEC_001 Hardcoded Secret" (ID + name from RuleNames)
       - "severity": "CRITICAL" / "HIGH" / etc.
     - Entries: format depends on mode
       - "file":     badge  ruleID  message  :line (current)
       - "rule":     badge  file:line  message
       - "severity": badge  ruleID  file:line  message
     - Remediation: only when opts.Verbose
     - Code frame: only when opts.Verbose (already gated)
  4. Summary banner (unchanged, except severity counts get color)
```

## Implementation Units

- [ ] **Unit 1: Add GroupBy and RuleNames to FormatOptions, add --group-by flag**

**Goal:** Extend FormatOptions with the new fields and wire the CLI flag.

**Requirements:** R1

**Dependencies:** None

**Files:**
- Modify: `pkg/output/table.go` (FormatOptions struct)
- Modify: `cmd/bouncerfox/main.go` (add flag, build RuleNames map, populate GroupBy)
- Test: `pkg/output/table_test.go`

**Approach:**
- Add `GroupBy string` and `RuleNames map[string]string` to `FormatOptions`
- Add `--group-by` flag with default `"file"` and validation for `file|rule|severity`
- Build `RuleNames` map from both `rules.Registry` and loaded custom rules in main.go before calling `FormatTable`
- Default `GroupBy` to `"file"` when empty for backward compatibility

**Patterns to follow:**
- Existing flag definitions at `main.go:538-554` (StringVar pattern)
- Existing format flag validation pattern at `main.go:354`

**Test scenarios:**
- Happy path: FormatTable with GroupBy="file" produces same output as before (backward compat)
- Happy path: FormatTable with GroupBy="" defaults to file grouping behavior
- Error path: invalid --group-by value rejected with clear error message

**Verification:**
- `go build` succeeds, `go test ./pkg/output/ ./cmd/bouncerfox/ -v` passes

---

- [ ] **Unit 2: Refactor FormatTable grouping logic to support multiple modes**

**Goal:** Generalize the grouping/sorting logic in FormatTable to work with file, rule, and severity keys.

**Requirements:** R1, R2, R3, R4, R5, R8

**Dependencies:** Unit 1

**Files:**
- Modify: `pkg/output/table.go` (FormatTable function body)
- Test: `pkg/output/table_test.go`

**Approach:**
- Extract a group-building function that takes the mode and returns groups with appropriate keys
- For file mode: key = relative file path, sort alphabetically (current behavior)
- For rule mode: key = ruleID, sort by the highest severity among the rule's findings then alphanumeric by ruleID
- For severity mode: key = severity string, sort in fixed order (critical, high, warn, info)
- Render group headers using `rm.bold()`:
  - File: just the file path (current)
  - Rule: `"SEC_001 Hardcoded Secret"` using `opts.RuleNames[ruleID]` with fallback to just ruleID
  - Severity: the severity label (e.g., `"critical"`)
- Add finding count appended to headers (all modes): e.g., `"(3 findings)"` or `"(1 finding)"`. No right-alignment, just append after the label.
- For rule/severity modes, each entry line includes `file:line` since the file is no longer the group header
- Define consistent column widths for each mode's format strings (R8). Badge is already fixed at 12 chars. Tune file:line and ruleID widths to align well with typical finding data.

**Patterns to follow:**
- Existing `group`/`entry` structs and `fileIndex` map pattern in `table.go:48-80`
- `evidenceFileAndLine()` helper for extracting file and line from evidence

**Test scenarios:**
- Happy path: group-by-file produces findings grouped under bold file name headers, sorted alphabetically
- Happy path: group-by-severity with mixed findings produces CRITICAL group first, then HIGH, WARN, INFO
- Happy path: group-by-severity entries within a group are sorted by file path then line number
- Happy path: group-by-rule groups findings under "RULE_ID Rule Name" headers
- Happy path: group-by-rule with rules at same severity tier are sorted alphanumerically by rule ID
- Happy path: group-by-rule with a rule having mixed severities (e.g., one critical and one high finding) sorts under the highest severity (critical)
- Happy path: group-by-rule falls back to just rule ID when RuleNames is nil or missing entry
- Edge case: group-by-severity with only one severity level produces a single group
- Edge case: single finding produces correct singular "1 finding" in header
- Edge case: findings with no file in evidence use "(unknown)" in rule/severity mode entries
- Integration: finding count in each group header matches actual number of entries in that group
- Happy path: columns align consistently across multiple findings in all three modes (R8)

**Verification:**
- `go test ./pkg/output/ -v` passes, all grouping modes produce correctly ordered and labeled output

---

- [ ] **Unit 3: Move remediation behind --verbose**

**Goal:** Remediation text only renders when `opts.Verbose` is true.

**Requirements:** R6

**Dependencies:** Unit 2

**Files:**
- Modify: `pkg/output/table.go` (remediation rendering in FormatTable)
- Test: `pkg/output/table_test.go`

**Approach:**
- Gate the remediation rendering block (currently at `table.go:104-109`) with `if opts.Verbose`
- This is a one-line change wrapping the existing remediation block

**Patterns to follow:**
- The code frame is already gated with `if opts.Verbose` at `table.go:110-112`

**Test scenarios:**
- Happy path: FormatTable with Verbose=false does not include remediation arrow or text
- Happy path: FormatTable with Verbose=true includes remediation arrow and text
- Edge case: finding with empty remediation string produces no extra line regardless of Verbose flag

**Verification:**
- `go test ./pkg/output/ -v` passes, existing tests updated to reflect new default behavior

---

- [ ] **Unit 4: Add severity-colored counts in summary banner**

**Goal:** Severity counts in the summary line use their respective colors in TTY mode.

**Requirements:** R7

**Dependencies:** Unit 2

**Files:**
- Modify: `pkg/output/table.go` (buildSevParts function)
- Modify: `pkg/output/display.go` (add severity color helper if needed)
- Test: `pkg/output/table_test.go`

**Approach:**
- Modify `buildSevParts` to accept a `renderMode` parameter
- For each severity count, wrap it with `rm.color()` using the matching ANSI code:
  - critical: `ansiRedBold`
  - high: `ansiRed`
  - warn: `ansiYellow`
  - info: `ansiCyan`
- In non-TTY / no-color mode, `rm.color()` is a no-op so counts appear uncolored automatically

**Patterns to follow:**
- `severityBadge()` in `display.go:70-86` uses the same color mapping
- `rm.color()` handles the TTY/no-color gating

**Test scenarios:**
- Happy path: summary with TTY mode contains ANSI color codes around severity counts
- Happy path: summary with NoColor=true contains no ANSI escape codes
- Edge case: zero-count severities are still omitted (existing behavior preserved)

**Verification:**
- `go test ./pkg/output/ -v` passes, colored summary renders correctly in TTY mode

## System-Wide Impact

- **Interaction graph:** Only the table formatter is affected. JSON and SARIF formatters are unchanged. The `--group-by` flag is ignored for non-table formats.
- **Error propagation:** No new error paths. Invalid `--group-by` values are caught at flag validation in main.go before scanning starts.
- **API surface parity:** The `FormatOptions` struct gains two fields. Existing callers that omit them get file grouping (zero-value default).
- **Unchanged invariants:** Exit codes, `--severity` filtering, `--verbose` code frames, SARIF/JSON output, and the summary banner structure are all unchanged.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| R6 (remediation behind verbose) is a breaking change for users who rely on seeing remediation in default output | Document in changelog. Remediation is still available via `--verbose`. |
| Rule names could be missing for custom rules | Fall back to just rule ID in headers when name is not in `RuleNames` map |

## Sources & References

- **Origin document:** [docs/brainstorms/2026-04-01-cli-output-polish-requirements.md](/home/mr47/workspace/bouncerfox-docs/docs/brainstorms/2026-04-01-cli-output-polish-requirements.md)
- Related code: `pkg/output/table.go`, `pkg/output/display.go`, `pkg/document/document.go`
- Industry research: ESLint, golangci-lint, Semgrep, Ruff, Trivy output format conventions
