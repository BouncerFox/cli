---
date: 2026-03-31
topic: reduce-false-positives
---

# Reduce False Positives in Scanning Rules

## Problem Frame

Running `bouncerfox scan` on the compound-engineering plugin (a well-maintained, widely-used Claude Code plugin) produces 2 critical and several warn-level findings that are false positives. Three rules need smarter detection logic to reduce noise without weakening security coverage.

## Requirements

**SEC_001: Env Var Reference Exclusion**

- R1. SEC_001 must not flag lines where the matched value is an environment variable reference rather than a hardcoded secret
- R2. Recognized env var patterns include at minimum: `ENV['...']`, `ENV["..."]`, `os.environ["..."]`, `os.environ['...']`, `os.getenv(...)`, `process.env.`, `$env:`, `${...}` shell variable syntax
- R3. The exclusion applies only to the broad catch-all patterns (the last two regexes in secretPatterns that match generic `api_key=...` / `password=...`), not to patterns matching specific key formats (e.g., `sk-ant-api03-...`, `AKIA...`, `ghp_...`)
- R4. The check must still flag lines where a real secret appears alongside an env var reference on the same line

**QA_007: Allow Colons in Skill Names**

- R5. QA_007 must accept colons (`:`) as valid characters in skill names, supporting namespace conventions like `ce:brainstorm`
- R6. Colons must not appear as the first or last character of a name
- R7. The updated regex should be `^[a-z0-9][a-z0-9:-]*[a-z0-9]$` or equivalent, with a single-char name fallback

**PS_004: Reduce Template Comment False Positives**

- R8. PS_004 should not flag HTML comments that are clearly template guidance or documentation (e.g., `<!-- Optional: Include this section only when... -->`)
- R9. Increase the default `min_comment_length` threshold from 25 to a higher value, or add heuristic filtering for comments that contain documentation-style language
- R10. The specific approach (higher threshold vs. heuristic) should be determined during planning based on analysis of real-world comment patterns

## Success Criteria

- Running `bouncerfox scan` on the compound-engineering plugin produces 0 critical false positives (SEC_001 env var refs no longer flagged)
- QA_007 passes for `ce:brainstorm` style names
- PS_004 does not flag short template/documentation comments from compound-engineering

## Scope Boundaries

- SEC_002 default allowlist is not changing — users configure their own
- SEC_003 behavior is not changing — it correctly flags destructive commands
- No new rules are being added
- No inline suppression mechanism — this was considered and rejected as a security risk (malicious skills could self-suppress their own findings)
- Fingerprint-based suppression is not being modified

## Key Decisions

- Colons allowed in skill names: Claude Code plugin ecosystem uses them as namespace separators, and they work in practice
- Inline suppression rejected: scanned files could use it to hide their own findings, defeating the purpose of security scanning. Users have `.bouncerfox.yml` and fingerprint maps for legitimate suppression needs
- SEC_001 exclusion targets the broad catch-all patterns only, not specific key format matchers — those are high-confidence and should still fire even if an env var is nearby

## Outstanding Questions

### Deferred to Planning

- [Affects R4][Technical] How to handle lines with both a real secret and an env var reference — should the exclusion be pattern-position-aware or whole-line?
- [Affects R9][Needs research] What is the right threshold or heuristic for PS_004? Analyze real-world comment lengths in popular plugins to find the sweet spot

## Next Steps

-> `/ce:plan` for structured implementation planning
