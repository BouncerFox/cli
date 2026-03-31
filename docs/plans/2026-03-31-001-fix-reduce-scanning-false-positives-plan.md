---
title: "fix: Reduce scanning false positives in SEC_001, QA_007, PS_004"
type: fix
status: active
date: 2026-03-31
origin: docs/brainstorms/2026-03-31-reduce-false-positives-requirements.md
---

# fix: Reduce scanning false positives in SEC_001, QA_007, PS_004

## Overview

Three scanning rules produce false positives when run against well-maintained plugins like compound-engineering. SEC_001 flags environment variable references as hardcoded secrets (critical severity). QA_007 rejects colon-namespaced skill names used by the plugin ecosystem. PS_004 flags short benign HTML comments. Each rule needs targeted detection improvements.

## Problem Frame

Running `bouncerfox scan` on compound-engineering produces 2 critical false positives (SEC_001 on `api_key: ENV['OPENAI_API_KEY']` and `api_key=os.environ["GEMINI_API_KEY"]`), 8 warn-level QA_007 findings on valid `ce:*` skill names, and 2 warn-level PS_004 findings on template guidance comments. These erode trust in scan results and create noise. (see origin: docs/brainstorms/2026-03-31-reduce-false-positives-requirements.md)

## Requirements Trace

- R1. SEC_001 must not flag lines where the matched value is an environment variable reference
- R2. Recognized env var patterns: `ENV['...']`, `ENV["..."]`, `os.environ[...]`, `os.getenv(...)`, `process.env.`, `$env:`, `${...}`
- R3. Exclusion applies only to catch-all patterns (indices 5 and 13 in `secretPatterns`), not specific key format patterns
- R4. Lines with a real secret alongside an env var ref must still be flagged — resolved by pattern ordering (specific patterns match first)
- R5. QA_007 must accept colons in skill names (e.g., `ce:brainstorm`)
- R6. Colons must not appear as first or last character
- R7. Updated regex with single-char name fallback
- R8. PS_004 should reduce false positives on template/documentation comments
- R9. Raise default `min_comment_length` from 25 to 80
- R10. Very long hidden comments (200+ chars) still flagged intentionally — content heuristics rejected as security bypass risk

## Scope Boundaries

- SEC_002 default allowlist unchanged
- SEC_003 behavior unchanged
- No new rules added
- No inline suppression mechanism (rejected as security risk — see origin)
- Fingerprint-based suppression unchanged
- No changes to rule-to-rule suppression map or engine pipeline

## Context & Research

### Relevant Code and Patterns

- `pkg/rules/sec.go:19-34` — `secretPatterns` slice. Index 13 is the broad catch-all: `(?i)(password|passwd|secret|api[_-]?key)\s*[:=]\s*['"]?\S{8,}`. Index 5 is hex catch-all: `(?i)(api[_-]?key|secret|token|password|auth)\s*[:=]\s*['"]?[0-9a-f]{32,}`
- `pkg/rules/sec.go:218-249` — `CheckSEC001()` iterates all patterns, breaks on first match. Specific format patterns (0-4, 6-12) precede catch-alls (5, 13), so they naturally take priority
- `pkg/rules/qa.go:14` — `validSkillNameRe = regexp.MustCompile('^[a-z0-9][a-z0-9-]*$')`
- `pkg/rules/qa.go:227-268` — `CheckQA007()` checks name format
- `pkg/rules/ps.go:18` — PS_004 threshold via `getIntParam(rc, "PS_004", "min_comment_length", 25)`
- `pkg/rules/params.go` — `DefaultRuleParams()` contains `"PS_004": {"min_comment_length": 25}`
- `pkg/rules/helpers.go:142-176` — `FindHTMLComments()` checks `len(commentContent) > minLength`
- RE2 regex constraint: no lookaheads or backreferences. Env var detection must be a two-pass check (match, then exclude)
- Test helpers: `newSkillDoc()`, `newClaudeMDDoc()`, `defaultRC()` in test files

## Key Technical Decisions

- **Env var exclusion via post-match check, not regex modification:** Go's RE2 engine lacks negative lookaheads. Instead of rewriting secretPatterns, add a post-match env var reference check that only applies to catch-all patterns. Rationale: keeps existing patterns intact, easier to maintain, and the two-pass approach is the established pattern in the codebase (SEC_018's entropy package uses similar exclusion logic)
- **Mark catch-all patterns by index, not by content inspection:** Define a constant or set identifying which pattern indices are catch-all (5, 13). This avoids runtime regex inspection and makes the boundary explicit. Rationale: the pattern slice is static and rarely changes; explicit indexing is clearer than heuristic classification
- **QA_007 regex update with OR for single-char names:** The new regex `^[a-z0-9]([a-z0-9:-]*[a-z0-9])?$` handles both single-char names (e.g., `a`) and multi-char names with colons. Rationale: simpler than maintaining two separate regexes
- **PS_004 threshold raise only, no content heuristics:** Raising from 25 to 80 eliminates short-comment noise. Content heuristics (e.g., detecting "template language" vs "prompt injection") were rejected because they create a bypass vector — attackers could write injections that mimic template language. Very long hidden comments remain flagged intentionally. Rationale: security scanner should surface hidden content for human review, not decide intent
- **Inline suppression rejected:** Scanned files could self-suppress their own security findings, defeating the scanner's purpose. Existing `.bouncerfox.yml` and fingerprint suppression provide legitimate escape hatches (see origin)

## Open Questions

### Resolved During Planning

- **R4: Lines with both real secret and env var ref:** Resolved by pattern ordering. Specific format patterns (indices 0-12) match before catch-alls (5, 13). If `sk-ant-api03-REAL_SECRET` appears on a line with `ENV['FOO']`, index 0 matches first and flags correctly. Env var exclusion only runs for catch-all matches.
- **R9: PS_004 threshold value:** 80 chars. Below this, comments are too short for meaningful prompt injection. Above this, they are legitimately worth reviewing. Users can tune via `.bouncerfox.yml`.

### Deferred to Implementation

- Exact env var reference regex pattern — the set of patterns (ENV, os.environ, process.env, etc.) is defined in R2, but the final compiled regex will be refined during implementation based on test cases

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

**SEC_001 env var exclusion flow:**

```
for each line:
  for each pattern in secretPatterns:
    if pattern matches line:
      if pattern index is catch-all (5 or 13):
        if line matches envVarRefRe:
          continue to next pattern  // skip this match
      flag finding, break
```

**Decision matrix for SEC_001 pattern behavior:**

| Pattern type | Env var on line? | Result |
|---|---|---|
| Specific format (0-4, 6-12) | Yes or No | Always flag |
| Catch-all hex (5) | No | Flag |
| Catch-all hex (5) | Yes | Skip (unlikely — hex values aren't env refs) |
| Catch-all broad (13) | No | Flag |
| Catch-all broad (13) | Yes | Skip |

## Implementation Units

- [ ] **Unit 1: SEC_001 — Add env var reference exclusion to catch-all patterns**

**Goal:** Prevent SEC_001 from flagging lines where the catch-all patterns match environment variable references instead of real secrets

**Requirements:** R1, R2, R3, R4

**Dependencies:** None

**Files:**
- Modify: `pkg/rules/sec.go`
- Test: `pkg/rules/sec_test.go`

**Approach:**
- Define an `envVarRefRe` regex matching the patterns from R2: `ENV\[`, `os\.environ\[`, `os\.getenv\(`, `process\.env\.`, `\$env:`, `\$\{[A-Z_]+\}`
- Define a set or constant identifying catch-all pattern indices (5, 13)
- In `CheckSEC001()`, after a pattern match, check if the matched pattern is catch-all AND the line matches `envVarRefRe`. If both conditions hold, `continue` to the next pattern instead of flagging
- The existing loop structure (break on first match) ensures specific format patterns still flag before catch-alls run

**Patterns to follow:**
- SEC_018's `ExtractCandidates()` in `pkg/entropy/entropy.go` — uses similar two-pass exclusion (match, then filter)
- Existing `secretPatterns` definition and `CheckSEC001` loop structure

**Test scenarios:**
- Happy path: `api_key: ENV['OPENAI_API_KEY']` in a skill doc → 0 findings (catch-all would match, but env var ref excludes it)
- Happy path: `api_key=os.environ["GEMINI_API_KEY"]` → 0 findings
- Happy path: `password: process.env.DB_PASSWORD` → 0 findings
- Happy path: `secret=${MY_SECRET}` → 0 findings
- Happy path: `api_key: os.getenv("API_KEY")` → 0 findings
- Happy path: `$env:API_KEY` → 0 findings
- Edge case: `sk-ant-api03-abcdef...` (90+ chars, specific format) → still flagged (index 0, not catch-all)
- Edge case: `ghp_abcdef123456...` (36 chars, GitHub PAT) → still flagged (index 7, not catch-all)
- Edge case: `password: actualplaintextpassword123` (no env var ref) → still flagged by catch-all
- Edge case: `api_key = "abc"` (value too short, < 8 chars) → 0 findings (catch-all doesn't match)
- Edge case: line with both `sk-ant-api03-REAL...` AND `ENV['FOO']` → flagged (specific pattern matches first)
- Edge case: `AKIA1234567890ABCDEF` with `ENV['X']` on same line → flagged (AWS pattern, index 11)

**Verification:**
- All existing SEC_001 tests still pass
- New env var reference tests pass
- Running `bouncerfox scan` on compound-engineering produces 0 SEC_001 findings on the dspy-ruby and gemini-imagegen skill files

---

- [ ] **Unit 2: QA_007 — Allow colons in skill names**

**Goal:** Update the skill name validation regex to accept colon-namespaced names like `ce:brainstorm`

**Requirements:** R5, R6, R7

**Dependencies:** None

**Files:**
- Modify: `pkg/rules/qa.go`
- Test: `pkg/rules/qa_test.go`

**Approach:**
- Replace `validSkillNameRe` from `^[a-z0-9][a-z0-9-]*$` to `^[a-z0-9]([a-z0-9:-]*[a-z0-9])?$`
- The outer group with `?` handles single-char names (e.g., `a`)
- The character class `[a-z0-9:-]` allows colons and hyphens in the middle
- The trailing `[a-z0-9]` ensures names don't end with `:` or `-`

**Patterns to follow:**
- Existing `CheckQA007` structure and test patterns in `qa_test.go`

**Test scenarios:**
- Happy path: `ce:brainstorm` → valid (no finding)
- Happy path: `ce:work` → valid
- Happy path: `my-skill` → valid (existing behavior preserved)
- Happy path: `a` → valid (single-char name)
- Happy path: `a1` → valid (two-char name)
- Edge case: `:bad` → invalid (starts with colon)
- Edge case: `bad:` → invalid (ends with colon)
- Edge case: `a:b:c` → valid (multiple colons allowed)
- Edge case: `My-Skill` → invalid (uppercase still rejected)
- Edge case: `my_skill` → invalid (underscore still rejected)
- Edge case: `-bad` → invalid (starts with hyphen, existing behavior)

**Verification:**
- All existing QA_007 tests still pass
- New colon tests pass
- Running `bouncerfox scan` on compound-engineering produces 0 QA_007 findings

---

- [ ] **Unit 3: PS_004 — Raise default comment length threshold**

**Goal:** Reduce false positives on short HTML comments by raising the default minimum length from 25 to 80

**Requirements:** R8, R9

**Dependencies:** None

**Files:**
- Modify: `pkg/rules/params.go`
- Test: `pkg/rules/ps_test.go`

**Approach:**
- Change the default value for `min_comment_length` in `DefaultRuleParams()` from `25` to `80`
- Update any test that depends on the old threshold value of 25
- Comments 200+ chars (like compound-engineering template guidance) will still be flagged — this is by design. Users can raise the threshold further via `.bouncerfox.yml`

**Patterns to follow:**
- Existing `DefaultRuleParams()` structure in `params.go`
- PS_004 test patterns in `ps_test.go`

**Test scenarios:**
- Happy path: comment of 30 chars → no finding (below new threshold)
- Happy path: comment of 79 chars → no finding (at boundary, below threshold)
- Happy path: comment of 81 chars → finding (above threshold)
- Edge case: comment of exactly 80 chars → no finding (threshold check is `>`, not `>=`)
- Edge case: comment of 200+ chars → finding (long hidden content still flagged)
- Edge case: unclosed comment → still flagged regardless of length (separate detection path)
- Edge case: custom `min_comment_length: 30` in config → uses custom value, not new default

**Verification:**
- All existing PS_004 tests pass (may need threshold updates in test assertions)
- Short benign comments no longer flagged
- Long hidden comments still flagged

## System-Wide Impact

- **Interaction graph:** SEC_001 caches matched lines in `doc.Parsed["_sec001_lines"]` for SEC_006 and SEC_018. Fewer SEC_001 matches (due to env var exclusion) means fewer lines in the cache, which means SEC_006/SEC_018 may now fire on lines that were previously suppressed by SEC_001. This is correct behavior — if the line isn't a secret, downstream entropy/base64 rules should evaluate it independently
- **Error propagation:** No change — rules return findings slices, no error paths affected
- **API surface parity:** The bouncerfox Python backend (if it mirrors these rules) may need the same changes. This is outside the scope of this plan
- **Unchanged invariants:** Rule registry ordering (SEC_001 first) is unchanged. Rule-to-rule suppression map is unchanged. Fingerprint computation is unchanged. All other rules are unchanged

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Env var regex too broad — matches non-env-var patterns and suppresses real secrets | Keep the regex tight (specific env var syntaxes only). Test with real secret patterns to verify they still fire |
| Env var regex too narrow — misses uncommon env var syntaxes | Start with the R2 set (covers Ruby, Python, Node, Shell, PowerShell). Expand later based on user reports |
| PS_004 threshold 80 too high — misses real prompt injection in 26-80 char comments | 80 is conservative. Short injections (< 80 chars) are unlikely to be effective. Users can lower via config |
| QA_007 colon support — colons break downstream tooling | Colons are already used in production by compound-engineering plugin. No known breakage |
| SEC_001 cache change affects SEC_006/SEC_018 | Correct behavior — fewer false SEC_001 matches means cleaner downstream evaluation. Verify with integration test |

## Sources & References

- **Origin document:** [docs/brainstorms/2026-03-31-reduce-false-positives-requirements.md](docs/brainstorms/2026-03-31-reduce-false-positives-requirements.md)
- Related code: `pkg/rules/sec.go`, `pkg/rules/qa.go`, `pkg/rules/ps.go`, `pkg/rules/params.go`, `pkg/rules/helpers.go`
- Test files: `pkg/rules/sec_test.go`, `pkg/rules/qa_test.go`, `pkg/rules/ps_test.go`
- Compound-engineering plugin: `~/.claude/plugins/cache/compound-engineering-plugin/compound-engineering/2.59.0/`
