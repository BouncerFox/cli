# BouncerFox CLI — Full Security Audit & Polish

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Comprehensive security audit, hardening, test coverage boost, lint enforcement, architecture review, and polish of the BouncerFox CLI scanner — inside-out sweep from core packages to CLI surface.

**Architecture:** Systematic inside-out audit. Each package gets: lint/quality review, code audit (architect + security engineer lens), hardening fixes, adversarial test cases, then `/simplify` before commit. Coverage targets: every package above 80% (except `cmd/bouncerfox/` which has no unit tests — integration-tested via smoke tests). Global additions: golangci-lint (strict), `.gitignore` cleanup.

**Tech Stack:** Go 1.25, Cobra CLI, gopkg.in/yaml.v3, golangci-lint

**IMPORTANT PROCESS NOTE:** After completing each task's code changes, run `/simplify` and follow its recommendations before committing. If you strongly disagree with a `/simplify` finding, surface it to the user for a decision rather than ignoring it.

**Known accepted risks:**
- **TOCTOU on file size:** Between `info.Size() > maxFileSize` check and `os.ReadFile()`, a file could grow beyond 1MB. Accepted: scanner is a local tool, not a network service.
- **`cmd/bouncerfox/` coverage:** Main package is tested via integration smoke tests, not unit tests. This is standard for CLI tools.

**Helper function signatures** (for test authors):
- `pkg/rules/sec_test.go`: `newSkillDoc(content string)`, `newClaudeMDDoc(content string)`, `newSettingsDoc(content string)`, `newMCPDoc(content string)`, `countFindings(findings, ruleID)`
- `pkg/engine/engine_test.go`: `makeSkill(t *testing.T, content string)`, `makeSettings(t *testing.T, content string)`, `makeMCP(t *testing.T, content string)`
- `pkg/custom/compiler_test.go`: `makeRule(id, severity string, match map[string]any)`, `doc(fileType, content string, parsed map[string]any)`, `mustCompile(t, rule)`

---

## File Map

### Files to create
- `.golangci.yml` — strict linter config
- `docs/architecture-review.md` — consolidated architecture assessment

### Files to modify
- `.gitignore` — add dist/, *.test, .env entries
- `.github/workflows/ci.yml` — fix Go version, add golangci-lint
- `Dockerfile` — add rootless user
- `cmd/bouncerfox/main.go` — WalkDir, hardening
- `pkg/document/document.go` — add String() method for severity
- `pkg/document/document_test.go` — unknown severity, String() tests
- `pkg/parser/frontmatter.go` — hardening (if needed after audit)
- `pkg/parser/json_config.go` — hardening (if needed after audit)
- `pkg/parser/router.go` — hardening (if needed after audit)
- `pkg/parser/normalize.go` — hardening (if needed after audit)
- `pkg/parser/codeblock.go` — hardening (if needed after audit)
- `pkg/parser/hash.go` — hardening (if needed after audit)
- `pkg/engine/engine.go` — architecture improvements (if needed)
- `pkg/config/config.go` — global state mutation documentation
- `pkg/custom/compiler.go` — resource limits on custom rules
- `pkg/custom/validation.go` — stricter validation
- `pkg/github/feedback.go` — response body limits
- `pkg/github/git.go` — audit
- `pkg/upload/upload.go` — response body limits
- Various test files — adversarial + coverage tests

---

### Task 1: Repo Hygiene — .gitignore, CI Fix, golangci-lint

**Files:**
- Modify: `.gitignore`
- Modify: `.github/workflows/ci.yml`
- Modify: `Dockerfile:6-8`
- Create: `.golangci.yml`

- [ ] **Step 0: Record baseline coverage**

Run coverage and record as benchmark for all subsequent tasks:

```bash
go test ./... -coverprofile=/tmp/baseline.out
go tool cover -func=/tmp/baseline.out | tail -20
```

Record current per-package coverage. Also run dependency vulnerability check:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

Also audit environment variable usage across the codebase:

```bash
grep -rn 'os.Getenv' --include='*.go' .
```

Verify no sensitive env vars (BOUNCERFOX_API_KEY, GITHUB_TOKEN) are logged or printed.

- [ ] **Step 1: Update .gitignore**

Current `.gitignore` only has `bf`. Add standard Go project ignores:

```gitignore
# Binary
bf
bouncerfox

# Build artifacts
dist/
*.test

# Environment
.env
.env.*

# Config with potential secrets
.bouncerfox.yml
.bouncerfox.yaml

# IDE
.idea/
.vscode/
*.swp
```

- [ ] **Step 2: Remove stale bf binary from git tracking**

Check if `bf` binary is tracked in git. If so, remove it:

```bash
git ls-files --error-unmatch bf 2>/dev/null && git rm --cached bf || echo "bf not tracked"
```

- [ ] **Step 3: Fix CI Go version mismatch**

In `.github/workflows/ci.yml`, line 19, change `go-version: '1.24'` to `go-version: '1.25'`. This must match `go.mod` (which declares `go 1.25.0`) and `.goreleaser.yml` (which uses 1.25).

```yaml
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'
```

- [ ] **Step 4: Add golangci-lint to CI**

Append a lint step to `.github/workflows/ci.yml`:

```yaml
      - name: golangci-lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: latest
```

- [ ] **Step 5: Create strict golangci-lint config**

Create `.golangci.yml` with strict linters enabled for a security-focused tool:

```yaml
run:
  timeout: 5m

linters:
  enable:
    - errcheck
    - gosec
    - gocritic
    - govet
    - ineffassign
    - staticcheck
    - unused
    - bodyclose
    - noctx
    - exhaustive
    - prealloc
    - unconvert
    - misspell
    - gofmt

linters-settings:
  gosec:
    excludes: []
  gocritic:
    enabled-tags:
      - diagnostic
      - style
      - performance
    disabled-checks:
      - hugeParam
  exhaustive:
    default-signifies-exhaustive: true

issues:
  max-issues-per-linter: 0
  max-same-issues: 0
  exclude-rules:
    - path: _test\.go
      linters:
        - gosec
        - errcheck
```

- [ ] **Step 6: Add rootless user to Dockerfile**

```dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
RUN go build -o /bf ./cmd/bouncerfox

FROM alpine:3.19
RUN adduser -D -u 1000 bouncerfox
COPY --from=builder /bf /usr/local/bin/bf
USER bouncerfox
ENTRYPOINT ["bf"]
```

- [ ] **Step 7: Install golangci-lint locally and run**

```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
golangci-lint run ./...
```

Fix ALL reported issues before proceeding. This may touch many files — fix them all.

- [ ] **Step 8: Run /simplify on all changes in this task**

- [ ] **Step 9: Run tests to verify nothing broke**

```bash
go test ./... -race
```

- [ ] **Step 10: Commit**

```bash
git add .golangci.yml .gitignore .github/workflows/ci.yml Dockerfile
# Plus any files fixed by golangci-lint
git commit -m "chore: add strict golangci-lint, fix CI Go version, harden Dockerfile"
```

---

### Task 2: document Package — Audit & Harden

**Files:**
- Modify: `pkg/document/document.go`
- Modify: `pkg/document/document_test.go`

- [ ] **Step 1: Audit document.go**

Read `pkg/document/document.go` (61 lines). Check:
- Are the severity constants exhaustive? Is there a default/unknown case?
- `Level()` returns -1 for unknown severity — is this safe for callers comparing levels?
- Should `ConfigDocument.Parsed` be typed more strongly than `map[string]any`?
- Is the `Evidence` map in `ScanFinding` safe from mutation after creation?

Document findings.

- [ ] **Step 2: Add String() method for FindingSeverity**

Add a `String()` method so severity can be printed cleanly:

```go
func (s FindingSeverity) String() string {
	return string(s)
}
```

- [ ] **Step 3: Write tests for unknown severity edge case**

Add to `pkg/document/document_test.go`:

```go
func TestSeverityLevel_Unknown(t *testing.T) {
	sev := FindingSeverity("bogus")
	if got := sev.Level(); got != -1 {
		t.Errorf("unknown severity Level() = %d, want -1", got)
	}
}

func TestSeverityLevel_Empty(t *testing.T) {
	sev := FindingSeverity("")
	if got := sev.Level(); got != -1 {
		t.Errorf("empty severity Level() = %d, want -1", got)
	}
}

func TestSeverityString(t *testing.T) {
	if got := SeverityCritical.String(); got != "critical" {
		t.Errorf("SeverityCritical.String() = %q, want %q", got, "critical")
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./pkg/document/ -v -race
```

- [ ] **Step 5: Run /simplify**

- [ ] **Step 6: Commit**

```bash
git add pkg/document/
git commit -m "harden: document package — add String(), test unknown severity"
```

---

### Task 3: parser Package — Audit & Adversarial Tests

**Files:**
- Modify: `pkg/parser/frontmatter.go` (if issues found)
- Modify: `pkg/parser/json_config.go` (if issues found)
- Modify: `pkg/parser/router.go` (if issues found)
- Modify: `pkg/parser/normalize.go` (if issues found)
- Modify: `pkg/parser/codeblock.go` (if issues found)
- Modify: `pkg/parser/hash.go` (if issues found)
- Modify: `pkg/parser/frontmatter_test.go`
- Modify: `pkg/parser/json_config_test.go`
- Modify: `pkg/parser/router_test.go`
- Modify: `pkg/parser/normalize_test.go`
- Modify: `pkg/parser/codeblock_test.go`
- Modify: `pkg/parser/hash_test.go`

- [ ] **Step 1: Audit all parser source files**

Read ALL 6 parser source files (router.go, normalize.go, codeblock.go, hash.go, frontmatter.go, json_config.go) plus ALL 6 test files. For each, check as architect:
- Are boundaries clean? Can a new file type be added without restructuring?
- Is the route table extensible?
- Are parsers isolated from each other?

And as security engineer:
- YAML parsing: anchors/aliases blocked, but are merge keys (`<<:`) blocked?
- Content size limits: 512KB enforced — is that before or after normalization?
- Binary detection: null byte check in first 8KB — sufficient?
- Unicode normalization: applied before parsing? Could bypass detection after normalization?
- JSON depth check: manual parser — could it miss nested arrays vs objects?
- Path traversal: `..` check in router — does it catch URL-encoded `%2e%2e`?
- Code block detection: could an attacker abuse unclosed fences to hide secrets?

- [ ] **Step 2: Fix any issues found in Step 1**

Apply fixes based on audit findings. Common ones to check:
- Ensure normalization happens BEFORE content size check (or after — verify order)
- Ensure YAML merge keys are handled
- Ensure path validation is robust

- [ ] **Step 3: Write adversarial tests for frontmatter parser**

Add to `pkg/parser/frontmatter_test.go`:

```go
func TestParseFrontmatterMD_OversizedContent(t *testing.T) {
	// 600KB content should be rejected
	huge := "---\nname: test\n---\n" + strings.Repeat("A", 600*1024)
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", huge)
	if doc.Parsed["_parse_error"] != true {
		t.Error("expected parse error for oversized content")
	}
	reason, _ := doc.Parsed["_reason"].(string)
	if reason != "content_too_large" {
		t.Errorf("expected reason content_too_large, got %q", reason)
	}
}

func TestParseFrontmatterMD_EmptyFrontmatter(t *testing.T) {
	content := "---\n---\nBody here"
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)
	if doc == nil {
		t.Fatal("expected non-nil doc for empty frontmatter")
	}
	body, _ := doc.Parsed["body"].(string)
	if body != "Body here" {
		t.Errorf("expected body 'Body here', got %q", body)
	}
}

func TestParseFrontmatterMD_MalformedYAML(t *testing.T) {
	content := "---\nname: [unclosed\n---\nBody"
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)
	if doc.Parsed["_parse_error"] != true {
		t.Error("expected parse error for malformed YAML")
	}
}

func TestParseFrontmatterMD_YAMLMergeKey(t *testing.T) {
	// YAML merge keys (<<:) use anchors/aliases — should be rejected
	content := "---\nbase: &base\n  key: value\nmerged:\n  <<: *base\n---\nBody"
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)
	if doc.Parsed["_parse_error"] != true {
		t.Error("expected parse error for YAML merge key (uses anchors)")
	}
}

func TestParseFrontmatterMD_DeepNestedYAML(t *testing.T) {
	// Build deeply nested YAML — should still parse (YAML has no depth limit by default)
	// but verify it doesn't crash
	var sb strings.Builder
	sb.WriteString("---\n")
	for i := 0; i < 50; i++ {
		sb.WriteString(strings.Repeat("  ", i))
		sb.WriteString(fmt.Sprintf("level%d:\n", i))
	}
	sb.WriteString(strings.Repeat("  ", 50))
	sb.WriteString("value: deep\n")
	sb.WriteString("---\nBody")
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", sb.String())
	if doc == nil {
		t.Fatal("expected non-nil doc")
	}
}

func TestParseFrontmatterMD_InvalidUTF8(t *testing.T) {
	// Invalid UTF-8 sequence that doesn't contain null bytes
	content := "---\nname: test\xff\xfe\n---\nBody"
	doc := ParseFrontmatterMD("skill_md", "SKILL.md", content)
	// Should not panic — either parse successfully or return parse error
	if doc == nil {
		t.Fatal("expected non-nil doc")
	}
}
```

- [ ] **Step 4: Write adversarial tests for JSON parser**

Add to `pkg/parser/json_config_test.go`:

```go
func TestParseJSONConfig_EmptyObject(t *testing.T) {
	doc := ParseJSONConfig("settings_json", "settings.json", "{}")
	if doc == nil {
		t.Fatal("expected non-nil doc for empty object")
	}
	if doc.Parsed["_parse_error"] == true {
		t.Error("empty object should not be a parse error")
	}
}

func TestParseJSONConfig_DeeplyNestedArrays(t *testing.T) {
	// Arrays also count for depth
	content := strings.Repeat("[", 15) + strings.Repeat("]", 15)
	doc := ParseJSONConfig("settings_json", "settings.json", content)
	if doc.Parsed["_parse_error"] != true {
		t.Error("expected parse error for deeply nested arrays")
	}
}

func TestParseJSONConfig_MixedNesting(t *testing.T) {
	// Objects inside arrays inside objects — stress the depth checker
	content := `{"a":[{"b":[{"c":[{"d":[{"e":[{"f":[{"g":[{"h":[{"i":[{"j":[{}]}]}]}]}]}]}]}]}]}]}`
	doc := ParseJSONConfig("settings_json", "settings.json", content)
	if doc.Parsed["_parse_error"] != true {
		t.Error("expected parse error for >10 nesting depth")
	}
}

func TestParseJSONConfig_InvalidUTF8(t *testing.T) {
	content := `{"key": "value\xff\xfe"}`
	doc := ParseJSONConfig("settings_json", "settings.json", content)
	// Should not panic
	if doc == nil {
		t.Fatal("expected non-nil doc")
	}
}

func TestFindJSONKeyLine_NestedKey(t *testing.T) {
	content := "{\n  \"outer\": {\n    \"inner\": true\n  }\n}"
	line := FindJSONKeyLine(content, "inner")
	if line != 3 {
		t.Errorf("expected line 3 for 'inner', got %d", line)
	}
}

func TestFindJSONKeyLine_MissingKey(t *testing.T) {
	content := `{"key": "value"}`
	line := FindJSONKeyLine(content, "missing")
	if line != 0 {
		t.Errorf("expected line 0 for missing key, got %d", line)
	}
}
```

- [ ] **Step 5: Write adversarial tests for router**

Add to `pkg/parser/router_test.go`:

```go
func TestIsGovernedFile_URLEncodedTraversal(t *testing.T) {
	// URL-encoded path traversal should not match
	if parser.IsGovernedFile("%2e%2e/%2e%2e/CLAUDE.md") {
		t.Error("URL-encoded path traversal should not be governed")
	}
}

func TestIsGovernedFile_NullByteInPath(t *testing.T) {
	if parser.IsGovernedFile("CLAUDE.md\x00.txt") {
		t.Error("null byte in path should not match")
	}
}

func TestIsGovernedFile_CaseSensitivity(t *testing.T) {
	// CLAUDE.md is case-sensitive
	if parser.IsGovernedFile("claude.md") {
		t.Error("lowercase claude.md should not be governed")
	}
}

func TestRouteAndParse_EmptyContent(t *testing.T) {
	doc := parser.RouteAndParse("CLAUDE.md", "")
	if doc == nil {
		t.Fatal("expected non-nil doc for empty content")
	}
}

func TestRouteAndParse_PathTraversalInContent(t *testing.T) {
	doc := parser.RouteAndParse("../../../CLAUDE.md", "content")
	if doc != nil {
		t.Error("path traversal should be rejected (nil doc)")
	}
}
```

- [ ] **Step 6: Write adversarial tests for normalize**

Add to `pkg/parser/normalize_test.go`:

```go
func TestNormalizeContent_NullBytes(t *testing.T) {
	// Null bytes should pass through normalization (binary detection happens elsewhere)
	input := "hello\x00world"
	got := parser.NormalizeContent(input)
	if !strings.Contains(got, "\x00") {
		t.Error("null bytes should not be stripped by normalization")
	}
}

func TestNormalizeContent_LargeInput(t *testing.T) {
	// 1MB of text should not cause OOM or timeout
	input := strings.Repeat("abcdefghij", 100_000)
	got := parser.NormalizeContent(input)
	if len(got) != len(input) {
		t.Errorf("expected same length, got %d vs %d", len(got), len(input))
	}
}

func TestNormalizeContent_MixedUnicode(t *testing.T) {
	// Fullwidth + HTML entities + normal text
	input := "ｒｍ &amp; &#60;script&#62;"
	got := parser.NormalizeContent(input)
	if !strings.Contains(got, "rm") {
		t.Error("fullwidth chars should be normalized to ASCII")
	}
	if !strings.Contains(got, "&") {
		t.Error("HTML entities should be unescaped")
	}
}
```

- [ ] **Step 7: Run tests**

```bash
go test ./pkg/parser/ -v -race -count=1
```

- [ ] **Step 8: Run /simplify**

- [ ] **Step 9: Commit**

```bash
git add pkg/parser/
git commit -m "harden: parser package — adversarial tests, audit fixes"
```

---

### Task 4: entropy Package — Audit & Edge Cases

**Files:**
- Modify: `pkg/entropy/entropy.go` (if issues found)
- Modify: `pkg/entropy/entropy_test.go`

- [ ] **Step 1: Audit entropy.go**

Read `pkg/entropy/entropy.go`. Check:
- `ShannonEntropy()`: division by zero risk? log2(0) risk?
- `ClassifyCharset()`: regex patterns — could they be abused with large inputs?
- `ExtractCandidates()`: tokenizer regex — performance on very long lines?
- `CredentialKeyRe`: could false positives cause excessive entropy checks?
- Is the token extraction regex safe against catastrophic backtracking? (RE2 = yes, but verify)

- [ ] **Step 2: Write edge case tests**

Add to `pkg/entropy/entropy_test.go`:

```go
func TestShannonEntropy_AllSameChar(t *testing.T) {
	got := ShannonEntropy("aaaaaaaaaa")
	if got != 0.0 {
		t.Errorf("all same chars should have 0 entropy, got %f", got)
	}
}

func TestShannonEntropy_MaxEntropy(t *testing.T) {
	// 256 unique bytes — maximum entropy for byte distribution
	var input []byte
	for i := 0; i < 256; i++ {
		input = append(input, byte(i))
	}
	got := ShannonEntropy(string(input))
	if got < 7.9 {
		t.Errorf("256 unique bytes should have ~8.0 entropy, got %f", got)
	}
}

func TestExtractCandidates_VeryLongLine(t *testing.T) {
	// 100KB line should not cause timeout
	line := strings.Repeat("a", 100_000) + " token=" + strings.Repeat("x", 40)
	candidates := ExtractCandidates(line, 16)
	// Should complete without panic/timeout; may or may not find the token
	_ = candidates
}

func TestExtractCandidates_EmptyLine(t *testing.T) {
	candidates := ExtractCandidates("", 16)
	if len(candidates) != 0 {
		t.Errorf("expected 0 candidates from empty line, got %d", len(candidates))
	}
}

func TestClassifyCharset_EmptyString(t *testing.T) {
	got := ClassifyCharset("")
	if got != "mixed" {
		t.Errorf("expected 'mixed' for empty string, got %q", got)
	}
}

func TestDetectContext_EmptyKey(t *testing.T) {
	got := DetectContext("")
	if got != "freetext" {
		t.Errorf("expected 'freetext' for empty key, got %q", got)
	}
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./pkg/entropy/ -v -race -count=1
```

- [ ] **Step 4: Run /simplify**

- [ ] **Step 5: Commit**

```bash
git add pkg/entropy/
git commit -m "harden: entropy package — edge case tests, audit"
```

---

### Task 5: fingerprint Package — Audit & Collision Tests

**Files:**
- Modify: `pkg/fingerprint/fingerprint_test.go`

- [ ] **Step 1: Audit fingerprint.go**

Read `pkg/fingerprint/fingerprint.go`. Check:
- Is the fingerprint truly content-stable (excludes all positional fields)?
- Could two different findings collide on fingerprint?
- Is `stableEvidence()` deterministic (sorted keys)?
- Are nil/empty evidence maps handled safely?

- [ ] **Step 2: Write collision resistance tests**

Add to `pkg/fingerprint/fingerprint_test.go`:

```go
func TestComputeFingerprint_DifferentRulesDontCollide(t *testing.T) {
	f1 := document.ScanFinding{
		RuleID:  "SEC_001",
		Message: "same message",
		Evidence: map[string]any{"snippet": "secret"},
	}
	f2 := document.ScanFinding{
		RuleID:  "SEC_002",
		Message: "same message",
		Evidence: map[string]any{"snippet": "secret"},
	}
	fp1 := ComputeFingerprint(f1)
	fp2 := ComputeFingerprint(f2)
	if fp1 == fp2 {
		t.Error("different rule IDs should produce different fingerprints")
	}
}

func TestComputeFingerprint_DifferentSnippetsDontCollide(t *testing.T) {
	f1 := document.ScanFinding{
		RuleID:  "SEC_001",
		Evidence: map[string]any{"snippet": "secret_a"},
	}
	f2 := document.ScanFinding{
		RuleID:  "SEC_001",
		Evidence: map[string]any{"snippet": "secret_b"},
	}
	fp1 := ComputeFingerprint(f1)
	fp2 := ComputeFingerprint(f2)
	if fp1 == fp2 {
		t.Error("different snippets should produce different fingerprints")
	}
}

func TestComputeFingerprint_NilEvidence(t *testing.T) {
	f := document.ScanFinding{
		RuleID:   "SEC_001",
		Evidence: nil,
	}
	fp := ComputeFingerprint(f)
	if len(fp) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars", len(fp))
	}
}

func TestComputeFingerprint_LargeEvidenceMap(t *testing.T) {
	ev := make(map[string]any)
	for i := 0; i < 100; i++ {
		ev[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_%d", i)
	}
	f := document.ScanFinding{
		RuleID:   "SEC_001",
		Evidence: ev,
	}
	fp := ComputeFingerprint(f)
	if len(fp) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars", len(fp))
	}
}

func TestComputeFingerprint_Deterministic(t *testing.T) {
	f := document.ScanFinding{
		RuleID:  "SEC_001",
		Evidence: map[string]any{
			"snippet": "abc",
			"key":     "val",
			"extra":   "data",
		},
	}
	fp1 := ComputeFingerprint(f)
	fp2 := ComputeFingerprint(f)
	if fp1 != fp2 {
		t.Error("same input must produce same fingerprint")
	}
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./pkg/fingerprint/ -v -race -count=1
```

- [ ] **Step 4: Run /simplify**

- [ ] **Step 5: Commit**

```bash
git add pkg/fingerprint/
git commit -m "harden: fingerprint package — collision resistance tests"
```

---

### Task 6: rules Package — Full Audit & Coverage Boost

**Files:**
- Modify: `pkg/rules/sec.go` (if issues found)
- Modify: `pkg/rules/qa.go` (if issues found)
- Modify: `pkg/rules/cfg.go` (if issues found)
- Modify: `pkg/rules/ps.go` (if issues found)
- Modify: `pkg/rules/helpers.go` (if issues found)
- Modify: `pkg/rules/registry.go` (if issues found)
- Modify: `pkg/rules/sec_test.go`
- Modify: `pkg/rules/qa_test.go`
- Modify: `pkg/rules/cfg_test.go`
- Modify: `pkg/rules/ps_test.go`
- Modify: `pkg/rules/helpers_test.go`

- [ ] **Step 1: Audit all rule source files**

Read every file in `pkg/rules/`. For each rule, check as security engineer:

**SEC rules:**
- SEC_001: Are regex patterns comprehensive? Do they catch newer token formats (GitHub fine-grained PATs `github_pat_`)?
- SEC_002: URL allowlist — is `*.example.com` only for tests or also shipped?
- SEC_003: Destructive commands — are `chmod 777`, `mkfs`, `dd` caught?
- SEC_004: Zero-width chars — is the Unicode range exhaustive?
- SEC_006: Base64 blobs — could legitimate long base64 (images, certs) cause false positives?
- SEC_009/010/011: Hook-based rules — what if hooks use env var expansion to hide patterns?
- SEC_012: Dangerous env vars — is `GIT_SSH_COMMAND` caught?
- SEC_014: MCP version pinning — what constitutes "pinned"?
- SEC_016: Plain HTTP — does it catch `http://0.0.0.0`?
- SEC_018: Entropy — are thresholds well-calibrated?

**QA rules:**
- Are boundary conditions handled (exactly 20 chars for QA_003, exactly 50KB for QA_008)?
- Is QA_005 prose detection robust against markdown syntax?

**CFG rules:**
- CFG_004: Shell injection in hooks — are all dangerous operators caught?
- CFG_009: Permissive flags — is the pattern comprehensive?

**PS rules:**
- PS_004: HTML comments — is the min length configurable and reasonable?

**Registry:**
- Is SEC_001 guaranteed to be first? What prevents reordering?

- [ ] **Step 2: Fix any issues found**

Apply fixes based on audit. Common additions:
- Add missing secret patterns (e.g., `github_pat_` format)
- Add missing destructive commands
- Add defensive comment in registry about ordering requirement

- [ ] **Step 3: Write adversarial tests for SEC rules**

Add to `pkg/rules/sec_test.go`:

```go
func TestSEC001_GitHubFineGrainedPAT(t *testing.T) {
	// github_pat_ format (fine-grained PATs)
	doc := newSkillDoc("github_pat_11ABCDEF0_abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz")
	findings := rules.CheckSEC001(doc)
	if len(findings) == 0 {
		t.Error("expected SEC_001 finding for github_pat_ token")
	}
}

func TestSEC001_NeverLeaksSecretValue(t *testing.T) {
	secret := "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	doc := newSkillDoc("api_key: " + secret)
	findings := rules.CheckSEC001(doc)
	for _, f := range findings {
		snippet, _ := f.Evidence["snippet"].(string)
		if strings.Contains(snippet, secret) {
			t.Error("SEC_001 must NEVER include the secret value in evidence")
		}
	}
}

func TestSEC003_AdditionalDestructiveCommands(t *testing.T) {
	commands := []string{
		"chmod 777 /etc/passwd",
		"mkfs.ext4 /dev/sda1",
		"dd if=/dev/zero of=/dev/sda",
	}
	for _, cmd := range commands {
		doc := newSkillDoc(cmd)
		findings := rules.CheckSEC003(doc)
		// These may or may not be caught — document the result
		t.Logf("SEC_003 on %q: %d findings", cmd, len(findings))
	}
}

func TestSEC016_PlainHTTP_ZeroAddress(t *testing.T) {
	doc := newMCPDoc(`{"mcpServers":{"test":{"command":"npx","args":["-y","server"],"env":{"URL":"http://0.0.0.0:3000"}}}}`)
	findings := rules.CheckSEC016(doc)
	// 0.0.0.0 should be treated like localhost (excluded)
	t.Logf("SEC_016 on http://0.0.0.0: %d findings", len(findings))
}

func TestSEC004_AllZeroWidthChars(t *testing.T) {
	// Test each zero-width char individually
	chars := []string{
		"\u200b", // zero-width space
		"\u200c", // zero-width non-joiner
		"\u200d", // zero-width joiner
		"\u2060", // word joiner
		"\ufeff", // BOM
	}
	for _, ch := range chars {
		doc := newSkillDoc("normal text" + ch + "more text")
		findings := rules.CheckSEC004(doc)
		if len(findings) == 0 {
			t.Errorf("SEC_004 missed zero-width char U+%04X", []rune(ch)[0])
		}
	}
}

func TestSEC018_BelowThreshold(t *testing.T) {
	// Low-entropy string that looks like a key but isn't
	doc := newSkillDoc("api_key: aaaaaaaabbbbbbbbcccccccc")
	findings := rules.CheckSEC018(doc)
	if len(findings) > 0 {
		t.Error("SEC_018 should not fire on low-entropy repetitive string")
	}
}
```

- [ ] **Step 4: Write edge case tests for QA/CFG/PS rules**

Add tests for boundary conditions:

```go
// In qa_test.go — uses newSkillDoc() helper (defined in sec_test.go, same package)
func TestQA003_ExactlyMinLength(t *testing.T) {
	// Default min is 20 chars — exactly 20 should pass
	content := "---\nname: test\ndescription: exactly twenty chars\n---\nBody content here."
	doc := newSkillDoc(content)
	findings := CheckQA003(doc)
	if len(findings) > 0 {
		t.Error("description with exactly min_description_length should not trigger")
	}
}

// In cfg_test.go — uses newSettingsDoc() helper (defined in sec_test.go, same package)
func TestCFG004_BacktickSubstitution(t *testing.T) {
	settings := "{\"hooks\":{\"PreToolUse\":[{\"matcher\":{\"tool_name\":\"*\"},\"hooks\":[{\"type\":\"command\",\"command\":\"echo `whoami`\"}]}]}}"
	doc := newSettingsDoc(settings)
	findings := CheckCFG004(doc)
	if len(findings) == 0 {
		t.Error("backtick command substitution in hook should trigger CFG_004")
	}
}

func TestCFG005_ExactlyTwenty(t *testing.T) {
	// Build JSON with exactly 20 tools
	var tools []string
	for i := 0; i < 20; i++ {
		tools = append(tools, fmt.Sprintf("\"Tool%d\"", i))
	}
	settings := fmt.Sprintf(`{"allowedTools":[%s]}`, strings.Join(tools, ","))
	doc := newSettingsDoc(settings)
	findings := CheckCFG005(doc)
	if len(findings) > 0 {
		t.Error("exactly 20 tools should not trigger CFG_005")
	}
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./pkg/rules/ -v -race -count=1
```

- [ ] **Step 6: Run /simplify**

- [ ] **Step 7: Commit**

```bash
git add pkg/rules/
git commit -m "harden: rules package — full audit, adversarial tests, coverage boost"
```

---

### Task 7: custom Package — Compiler Hardening & Coverage Boost

**Files:**
- Modify: `pkg/custom/compiler.go`
- Modify: `pkg/custom/validation.go`
- Modify: `pkg/custom/compiler_test.go`
- Modify: `pkg/custom/validation_test.go`

**Target:** Coverage from 13.6% (compileMatch) / 35.3% (extractCodeBlockLines) / 38.9% (validatePerFileType) → 80%+

- [ ] **Step 1: Audit compiler.go for supply chain attack vectors**

Read `pkg/custom/compiler.go` carefully. Check:
- Can a malicious `.bouncerfox.yml` custom rule cause:
  - Regex DoS? (RE2 is safe, but verify regex size limits)
  - Memory exhaustion? (deeply nested all_of/any_of combinators)
  - CPU exhaustion? (collection iteration limit = 1000 — is it enforced everywhere?)
  - Information leakage? (error messages revealing file contents)
- Is `collectionIterationLimit` enforced in ALL collection-iterating paths?
- Can `resolveFieldPath()` with crafted dot-paths access unintended data?
- Are recursive combinators (all_of containing all_of containing...) depth-limited?

- [ ] **Step 2: Add recursion depth limit to compiler**

Add a nesting depth limit to prevent malicious deeply-nested custom rules:

In `pkg/custom/compiler.go`, modify `compileMatch` to track depth:

```go
const maxMatchNestingDepth = 10

func compileMatchWithDepth(m map[string]any, ctx ruleCtx, depth int) (func(*document.ConfigDocument) []document.ScanFinding, error) {
	if depth > maxMatchNestingDepth {
		return nil, fmt.Errorf("match nesting exceeds maximum depth (%d)", maxMatchNestingDepth)
	}
	// ... existing logic, passing depth+1 to recursive calls
}
```

- [ ] **Step 3: Add regex size limit**

Before compiling user-provided regex patterns, enforce a size limit:

```go
const maxRegexLength = 4096

func compileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexLength {
		return nil, fmt.Errorf("regex pattern exceeds maximum length (%d chars)", maxRegexLength)
	}
	return regexp.Compile(pattern)
}
```

Use this wrapper everywhere `regexp.Compile` is called with user input.

- [ ] **Step 4: Write tests for all untested match primitives**

Add comprehensive tests for each primitive to `pkg/custom/compiler_test.go`:

```go
func TestContentContains_Match(t *testing.T) {
	rule := makeRule("CUST_001", "warn", map[string]any{
		"type": "content_contains",
		"value": "dangerous",
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	d := doc("skill_md", "this is dangerous content", nil)
	findings := fn(d)
	if len(findings) == 0 {
		t.Error("expected finding for content_contains match")
	}
}

func TestContentContains_NoMatch(t *testing.T) {
	rule := makeRule("CUST_001", "warn", map[string]any{
		"type": "content_contains",
		"value": "dangerous",
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	d := doc("skill_md", "this is safe content", nil)
	findings := fn(d)
	if len(findings) != 0 {
		t.Error("expected no findings for non-matching content")
	}
}

func TestFieldExists_Present(t *testing.T) {
	rule := makeRule("CUST_001", "warn", map[string]any{
		"type": "field_exists",
		"field": "frontmatter.name",
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	d := doc("skill_md", "", map[string]any{
		"frontmatter": map[string]any{"name": "test"},
	})
	findings := fn(d)
	if len(findings) == 0 {
		t.Error("expected finding when field exists")
	}
}

func TestFieldMissing_Absent(t *testing.T) {
	rule := makeRule("CUST_001", "warn", map[string]any{
		"type": "field_missing",
		"field": "frontmatter.tools",
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	d := doc("skill_md", "", map[string]any{
		"frontmatter": map[string]any{"name": "test"},
	})
	findings := fn(d)
	if len(findings) == 0 {
		t.Error("expected finding when field is missing")
	}
}

func TestAllOf_AllMatch(t *testing.T) {
	rule := makeRule("CUST_001", "warn", map[string]any{
		"type": "all_of",
		"children": []any{
			map[string]any{"type": "content_contains", "value": "foo"},
			map[string]any{"type": "content_contains", "value": "bar"},
		},
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	d := doc("skill_md", "foo and bar", nil)
	findings := fn(d)
	if len(findings) == 0 {
		t.Error("expected finding when all children match")
	}
}

func TestAllOf_PartialMatch(t *testing.T) {
	rule := makeRule("CUST_001", "warn", map[string]any{
		"type": "all_of",
		"children": []any{
			map[string]any{"type": "content_contains", "value": "foo"},
			map[string]any{"type": "content_contains", "value": "missing"},
		},
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	d := doc("skill_md", "only foo here", nil)
	findings := fn(d)
	if len(findings) != 0 {
		t.Error("expected no findings when not all children match")
	}
}

func TestAnyOf_OneMatches(t *testing.T) {
	rule := makeRule("CUST_001", "warn", map[string]any{
		"type": "any_of",
		"children": []any{
			map[string]any{"type": "content_contains", "value": "foo"},
			map[string]any{"type": "content_contains", "value": "missing"},
		},
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	d := doc("skill_md", "only foo here", nil)
	findings := fn(d)
	if len(findings) == 0 {
		t.Error("expected finding when any child matches")
	}
}

func TestNot_Inverts(t *testing.T) {
	rule := makeRule("CUST_001", "warn", map[string]any{
		"type": "not",
		"child": map[string]any{"type": "content_contains", "value": "forbidden"},
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	// Content does NOT contain "forbidden" — not inverts → finding
	d := doc("skill_md", "safe content", nil)
	findings := fn(d)
	if len(findings) == 0 {
		t.Error("expected finding when not condition is satisfied (content doesn't match)")
	}
}

func TestPerFileType_Dispatch(t *testing.T) {
	rule := makeRule("CUST_001", "warn", map[string]any{
		"type": "per_file_type",
		"branches": map[string]any{
			"skill_md": map[string]any{
				"type": "content_contains",
				"value": "skill-specific",
			},
			"settings_json": map[string]any{
				"type": "content_contains",
				"value": "settings-specific",
			},
		},
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	d := doc("skill_md", "this is skill-specific", nil)
	findings := fn(d)
	if len(findings) == 0 {
		t.Error("expected finding for matching file type branch")
	}
}

func TestCompile_NestingDepthLimit(t *testing.T) {
	// Build deeply nested all_of → should be rejected
	inner := map[string]any{
		"type": "content_contains",
		"value": "x",
	}
	for i := 0; i < 15; i++ {
		inner = map[string]any{
			"type": "all_of",
			"children": []any{inner},
		}
	}
	rule := makeRule("CUST_001", "warn", inner)
	_, err := custom.Compile(rule)
	if err == nil {
		t.Error("expected error for deeply nested match (exceeds depth limit)")
	}
}

func TestCompile_RegexSizeLimit(t *testing.T) {
	// 10KB regex pattern — should be rejected
	hugePattern := strings.Repeat("a", 10_000)
	rule := makeRule("CUST_001", "warn", map[string]any{
		"type": "line_pattern",
		"pattern": hugePattern,
	})
	_, err := custom.Compile(rule)
	if err == nil {
		t.Error("expected error for oversized regex pattern")
	}
}
```

- [ ] **Step 5: Write tests for extractCodeBlockLines branches**

```go
func TestExtractCodeBlockLines_MapIntBool(t *testing.T) {
	doc := &document.ConfigDocument{
		Parsed: map[string]any{
			"code_block_lines": map[int]bool{3: true, 5: true},
		},
	}
	// Test through a rule that uses code_block_lines
	// ... (use line_pattern with skip_code_blocks)
}

func TestExtractCodeBlockLines_NilParsed(t *testing.T) {
	doc := &document.ConfigDocument{
		Parsed: nil,
	}
	// Should not panic
	rule := makeRule("CUST_001", "warn", map[string]any{
		"type": "line_pattern",
		"pattern": "test",
	})
	fn, err := custom.Compile(rule)
	if err != nil {
		t.Fatal(err)
	}
	findings := fn(d)
	_ = findings // just verify no panic
}
```

- [ ] **Step 6: Write validation coverage tests**

Add to `pkg/custom/validation_test.go`:

```go
func TestValidate_PerFileType_InvalidBranch(t *testing.T) {
	rule := map[string]any{
		"id": "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"type": "per_file_type",
			"branches": map[string]any{
				"skill_md": "not a map",
			},
		},
	}
	err := custom.Validate(rule)
	if err == nil {
		t.Error("expected validation error for non-map branch")
	}
}

func TestValidate_PerFileType_EmptyBranches(t *testing.T) {
	rule := map[string]any{
		"id": "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"type": "per_file_type",
			"branches": map[string]any{},
		},
	}
	err := custom.Validate(rule)
	if err == nil {
		t.Error("expected validation error for empty branches")
	}
}

func TestValidate_NotCombinator_MissingChild(t *testing.T) {
	rule := map[string]any{
		"id": "CUST_001",
		"severity": "warn",
		"match": map[string]any{
			"type": "not",
			// missing "child"
		},
	}
	err := custom.Validate(rule)
	if err == nil {
		t.Error("expected validation error for not without child")
	}
}
```

- [ ] **Step 7: Run tests and check coverage**

```bash
go test ./pkg/custom/ -v -race -count=1 -coverprofile=/tmp/custom.out
go tool cover -func=/tmp/custom.out
```

Verify compileMatch, extractCodeBlockLines, and validatePerFileType are now >80%.

- [ ] **Step 8: Run /simplify**

- [ ] **Step 9: Commit**

```bash
git add pkg/custom/
git commit -m "harden: custom compiler — depth limits, regex limits, coverage >80%"
```

---

### Task 8: engine Package — Audit & Resource Limits

**Files:**
- Modify: `pkg/engine/engine.go` (if issues found)
- Modify: `pkg/engine/engine_test.go`
- Modify: `pkg/engine/integration_test.go`

- [ ] **Step 1: Audit engine.go**

Read `pkg/engine/engine.go`. Check as architect:
- Is the Scan function easy to extend? Could it support parallel rule execution?
- Is the suppression map logic correct for all edge cases?
- Are there any hidden O(n^2) or worse performance issues?
- Is `ruleSuppressionMap` easily extensible when new rules are added?
- Could the engine be used as a library (not just from CLI)?

Check as security engineer:
- Can `locationKey()` produce collisions? (file:line format)
- Does the dedup via fingerprint correctly prevent duplicate findings?
- What happens with 10,000 findings? 100,000? Is there an implicit cap?
- Is `rules.Registry` iteration order guaranteed? (ordered slice — yes)
- Does global `rules.RuleParams` mutation in config.ToScanOptions() affect concurrent scans?

- [ ] **Step 2: Add comment about global state risk**

Add a prominent comment in `engine.go` about the global state issue:

```go
// WARNING: rules.RuleParams is global mutable state. config.ToScanOptions()
// mutates it before Scan() is called. This means Scan is NOT safe for
// concurrent use with different configs. If we ever need concurrent scans
// with different configs, RuleParams must be passed per-scan.
```

- [ ] **Step 3: Write adversarial engine tests**

Add to `pkg/engine/engine_test.go`:

```go
func TestScan_ManyFindings(t *testing.T) {
	// Generate a document that triggers many findings
	var content strings.Builder
	for i := 0; i < 100; i++ {
		content.WriteString(fmt.Sprintf("sk-ant-api03-%d\n", i))
	}
	doc := makeSkill(t, content.String())
	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{})
	// Should complete without OOM or timeout
	if result.FilesScanned != 1 {
		t.Errorf("expected 1 file scanned, got %d", result.FilesScanned)
	}
}

func TestScan_NilDocInSlice(t *testing.T) {
	// Should handle nil docs gracefully
	docs := []*document.ConfigDocument{nil, makeSkill(t, "clean")}
	// This will likely panic — fix if so
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Scan panicked on nil doc: %v", r)
		}
	}()
	_ = engine.Scan(docs, engine.ScanOptions{})
}

func TestScan_EmptyContent(t *testing.T) {
	doc := makeSkill(t, "")
	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{})
	if result.FilesScanned != 1 {
		t.Errorf("expected 1 file scanned, got %d", result.FilesScanned)
	}
}

func TestScan_SuppressionChain(t *testing.T) {
	// Test the full suppression chain: SEC_001 → SEC_018 → SEC_006
	// A line with a secret should only produce SEC_001, not SEC_018 or SEC_006
	doc := makeSkill(t, "key: sk-ant-api03-" + strings.Repeat("x", 50))
	result := engine.Scan([]*document.ConfigDocument{doc}, engine.ScanOptions{
		EnabledRules: []string{"SEC_001", "SEC_018", "SEC_006"},
	})
	for _, f := range result.Findings {
		if f.RuleID == "SEC_018" || f.RuleID == "SEC_006" {
			t.Errorf("rule %s should be suppressed by SEC_001 on same line", f.RuleID)
		}
	}
}
```

- [ ] **Step 4: Fix nil doc handling if needed**

If `TestScan_NilDocInSlice` panics, add a nil check in the scan loop:

```go
for _, doc := range docs {
	if doc == nil {
		continue
	}
	// ... existing logic
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./pkg/engine/ -v -race -count=1
```

- [ ] **Step 6: Run /simplify**

- [ ] **Step 7: Commit**

```bash
git add pkg/engine/
git commit -m "harden: engine package — nil safety, suppression chain test, global state warning"
```

---

### Task 9: config Package — Audit & Malicious Config Tests

**Files:**
- Modify: `pkg/config/config.go` (if issues found)
- Modify: `pkg/config/config_test.go`

- [ ] **Step 1: Audit config.go**

Read `pkg/config/config.go`. Check:
- Global state mutation: `ToScanOptions()` modifies `rules.RuleParams` — this is a design smell. Document it clearly.
- Can a malicious `.bouncerfox.yml` cause:
  - YAML bomb? (yaml.v3 handles anchors/aliases — but is it limited?)
  - Memory exhaustion via huge ignore lists?
  - Rule params that break rule logic (negative thresholds, empty patterns)?
- `readConfigFile()`: does it follow symlinks?
- `log.Printf` for unknown rules — should this be stderr?
- `clampSeverity`: correct for all edge cases?

- [ ] **Step 2: Write malicious config tests**

Add to `pkg/config/config_test.go`:

```go
func TestLoadConfig_HugeIgnoreList(t *testing.T) {
	patterns := make([]string, 10_000)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("pattern_%d/**", i)
	}
	content := "ignore:\n"
	for _, p := range patterns {
		content += fmt.Sprintf("  - %q\n", p)
	}
	dir := writeConfig(t, content)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Ignore) != 10_000 {
		t.Errorf("expected 10000 ignore patterns, got %d", len(cfg.Ignore))
	}
}

func TestLoadConfig_MaliciousRuleParams(t *testing.T) {
	content := `
rules:
  SEC_018:
    params:
      threshold_credential_hex: -1.0
      min_length_credential: 0
`
	dir := writeConfig(t, content)
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	// The negative threshold and zero min length should be accepted by config
	// but the rules themselves should handle these defensively
	_ = cfg
}

func TestLoadConfig_UnknownFields(t *testing.T) {
	content := `
profile: recommended
unknown_field: value
extra_stuff:
  nested: true
`
	dir := writeConfig(t, content)
	cfg, err := config.LoadConfig(dir)
	// Should not error — unknown fields are silently ignored by yaml.v3
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Profile != "recommended" {
		t.Errorf("expected profile 'recommended', got %q", cfg.Profile)
	}
}

func TestLoadConfig_EmptyFile(t *testing.T) {
	dir := writeConfig(t, "")
	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Profile != "recommended" {
		t.Errorf("expected default profile, got %q", cfg.Profile)
	}
}

func TestToScanOptions_ConflictingOverrides(t *testing.T) {
	// Rule is both disabled and has severity override
	f := false
	sev := document.SeverityHigh
	cfg := &config.Config{
		Profile: "all_rules",
		Rules: map[string]config.RuleConfig{
			"QA_001": {
				Enabled:  &f,
				Severity: &sev,
			},
		},
	}
	opts := cfg.ToScanOptions()
	// QA_001 should be in disabled list
	found := false
	for _, d := range opts.DisabledRules {
		if d == "QA_001" {
			found = true
		}
	}
	if !found {
		t.Error("disabled rule QA_001 should be in DisabledRules")
	}
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./pkg/config/ -v -race -count=1
```

- [ ] **Step 4: Run /simplify**

- [ ] **Step 5: Commit**

```bash
git add pkg/config/
git commit -m "harden: config package — malicious config tests, edge cases"
```

---

### Task 10: output Package — Audit & Special Character Tests

**Files:**
- Modify: `pkg/output/json.go` (if issues found)
- Modify: `pkg/output/sarif.go` (if issues found)
- Modify: `pkg/output/table.go` (if issues found)
- Modify: `pkg/output/output_test.go`

- [ ] **Step 1: Audit all output formatters**

Read all files in `pkg/output/`. Check:
- JSON output: are special characters escaped properly (newlines, quotes, null bytes in messages)?
- SARIF output: does it validate against the SARIF 2.1.0 schema?
- Table output: could ANSI injection in finding messages break terminal?
- Are nil/empty findings handled in all formatters?
- Is the version hardcoded in sarif.go? Should it use the ldflags version?

- [ ] **Step 2: Write tests for all three formatters**

Add to `pkg/output/output_test.go`:

```go
// ---- JSON formatter ----

func TestFormatJSON_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	err := output.FormatJSON(testFindings(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}
	if parsed["version"] != "1.0" {
		t.Errorf("expected version 1.0, got %v", parsed["version"])
	}
}

func TestFormatJSON_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	err := output.FormatJSON(nil, &buf)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("empty findings should produce valid JSON: %v", err)
	}
}

func TestFormatJSON_SpecialCharsInMessage(t *testing.T) {
	findings := []document.ScanFinding{{
		RuleID:   "SEC_001",
		Severity: document.SeverityCritical,
		Message:  "message with \"quotes\" and\nnewlines and\ttabs",
		Evidence: map[string]any{"file": "test.md", "line": 1},
	}}
	var buf bytes.Buffer
	err := output.FormatJSON(findings, &buf)
	if err != nil {
		t.Fatal(err)
	}
	// Must be valid JSON despite special chars
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("special chars in message broke JSON: %v", err)
	}
}

// ---- SARIF formatter ----

func TestFormatSARIF_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	err := output.FormatSARIF(testFindings(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
	if parsed["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", parsed["version"])
	}
}

func TestFormatSARIF_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	err := output.FormatSARIF(nil, &buf)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("empty SARIF should be valid JSON: %v", err)
	}
}

// ---- Table formatter ----

func TestFormatTable_ANSIInjection(t *testing.T) {
	findings := []document.ScanFinding{{
		RuleID:   "SEC_001",
		Severity: document.SeverityCritical,
		Message:  "message with \x1b[31mANSI codes\x1b[0m",
		Evidence: map[string]any{"file": "test.md", "line": 1},
	}}
	var buf bytes.Buffer
	err := output.FormatTable(findings, &buf)
	if err != nil {
		t.Fatal(err)
	}
	// Table output contains ANSI by design (colors), so this is informational
	_ = buf.String()
}

func TestFormatTable_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	err := output.FormatTable(nil, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Found 0 finding(s)") {
		t.Error("expected zero-finding summary")
	}
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./pkg/output/ -v -race -count=1
```

- [ ] **Step 4: Run /simplify**

- [ ] **Step 5: Commit**

```bash
git add pkg/output/
git commit -m "harden: output package — JSON/SARIF/table tests, special char handling"
```

---

### Task 11: github Package — Coverage Boost & Token Safety

**Files:**
- Modify: `pkg/github/feedback.go` (if issues found)
- Modify: `pkg/github/git.go` (audit)
- Modify: `pkg/github/feedback_test.go`

**Target:** Coverage from 41.7% (DetectRepoInfo) → 80%+

- [ ] **Step 1: Audit feedback.go for token safety**

Read `pkg/github/feedback.go`. Check:
- Is the token ever logged or included in error messages?
- Is `doRequest()` setting the token in the Authorization header safely?
- Does `baseURL` being a package-level var create test isolation issues?
- Are HTTP response bodies being fully read/closed (preventing connection leaks)?
- Can a malicious GitHub API response crash the client (huge bodies, malformed JSON)?
- Is `findExistingComment()` paginating? (Only fetches first 100 comments)

- [ ] **Step 2: Add response body size limit**

In `doRequest()`, add a limit on response body reads to prevent OOM from malicious responses:

```go
// Limit response body to 10 MB to prevent OOM from malicious responses.
const maxResponseSize = 10 * 1024 * 1024
data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
```

- [ ] **Step 3: Write coverage-boosting tests**

Add to `pkg/github/feedback_test.go`:

```go
func TestDetectRepoInfo_GitRemoteFallback(t *testing.T) {
	// Unset GITHUB_REPOSITORY to force git remote fallback
	t.Setenv("GITHUB_REPOSITORY", "")
	// This will try to run git — may fail in test env, which is fine
	_, _, err := DetectRepoInfo()
	// We just verify it doesn't panic; error is expected in CI
	_ = err
}

func TestParseGitRemote_MalformedURL(t *testing.T) {
	cases := []string{
		"",
		"just-a-string",
		"ftp://example.com/repo",
		"git@github.com:",
		"https://github.com/only-owner",
	}
	for _, c := range cases {
		_, _, err := parseGitRemote(c)
		if err == nil {
			t.Errorf("parseGitRemote(%q) should return error", c)
		}
	}
}

func TestParseGitRemote_TrailingSlash(t *testing.T) {
	o, r, err := parseGitRemote("https://github.com/owner/repo/")
	if err != nil {
		// Document behavior — trailing slash may or may not work
		t.Logf("trailing slash: %v", err)
		return
	}
	t.Logf("trailing slash parsed: %s/%s", o, r)
	_ = o
	_ = r
}

func TestBuildCommentBody_PipeInMessage(t *testing.T) {
	findings := []document.ScanFinding{{
		RuleID:   "SEC_001",
		Severity: document.SeverityCritical,
		Message:  "pipe | in message",
		Evidence: map[string]any{"file": "f.md", "line": 1},
	}}
	body := buildCommentBody(findings)
	if !strings.Contains(body, `\|`) {
		t.Error("pipes in messages should be escaped for markdown tables")
	}
}

func TestPostCheckRun_EmptyFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": float64(1)})
	}))
	defer srv.Close()

	orig := baseURL
	baseURL = srv.URL
	defer func() { baseURL = orig }()

	err := PostCheckRun(context.Background(), CheckRunOptions{
		Token: "tok", Owner: "o", Repo: "r", CommitSHA: "sha",
		Findings: nil,
	})
	if err != nil {
		t.Fatalf("empty findings: %v", err)
	}
}

func TestEscapeMarkdown(t *testing.T) {
	cases := []struct{ in, want string }{
		{"no pipes", "no pipes"},
		{"has | pipe", `has \| pipe`},
		{"multi || pipes", `multi \|\| pipes`},
	}
	for _, c := range cases {
		got := escapeMarkdown(c.in)
		if got != c.want {
			t.Errorf("escapeMarkdown(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEvidenceFileAndLine_TypeVariants(t *testing.T) {
	cases := []struct {
		name string
		ev   map[string]any
		file string
		line int
	}{
		{"int line", map[string]any{"file": "f.md", "line": 5}, "f.md", 5},
		{"float64 line", map[string]any{"file": "f.md", "line": float64(5)}, "f.md", 5},
		{"int64 line", map[string]any{"file": "f.md", "line": int64(5)}, "f.md", 5},
		{"no line", map[string]any{"file": "f.md"}, "f.md", 0},
		{"no file", map[string]any{"line": 5}, "", 5},
		{"nil evidence", nil, "", 0},
	}
	for _, c := range cases {
		file, line := evidenceFileAndLine(c.ev)
		if file != c.file || line != c.line {
			t.Errorf("%s: got file=%q line=%d, want file=%q line=%d", c.name, file, line, c.file, c.line)
		}
	}
}
```

- [ ] **Step 4: Run tests and check coverage**

```bash
go test ./pkg/github/ -v -race -count=1 -coverprofile=/tmp/github.out
go tool cover -func=/tmp/github.out
```

- [ ] **Step 5: Run /simplify**

- [ ] **Step 6: Commit**

```bash
git add pkg/github/
git commit -m "harden: github package — response limits, coverage >80%, token safety"
```

---

### Task 12: upload Package — Coverage Boost & Payload Safety

**Files:**
- Modify: `pkg/upload/upload.go` (if issues found)
- Modify: `pkg/upload/upload_test.go`

**Target:** Coverage from 47.8% → 80%+

- [ ] **Step 1: Audit upload.go**

Read `pkg/upload/upload.go`. Check:
- Is `doUpload()` test helper duplicating code from `Upload()`? Should it be refactored?
- Is response body size limited?
- Is the API key sent only over HTTPS?
- Could the payload leak sensitive data (secrets from findings)?
- `buildFindings()` copies evidence — is it a deep copy? Could mutations leak back?

- [ ] **Step 2: Add response body size limit**

Same pattern as github package — add `io.LimitReader` for response body:

```go
body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
```

- [ ] **Step 3: Write coverage-boosting tests**

Add to `pkg/upload/upload_test.go`:

```go
func TestTransformEvidence_Anonymous(t *testing.T) {
	ev := map[string]any{"file": "/path/to/file.md", "line": 5, "snippet": "data"}
	got := transformEvidence(ev, false, true)
	if _, hasFile := got["file"]; hasFile {
		t.Error("anonymous mode should remove file from evidence")
	}
	if got["snippet"] != "data" {
		t.Error("anonymous mode should preserve non-file evidence")
	}
}

func TestTransformEvidence_StripPaths(t *testing.T) {
	ev := map[string]any{"file": "/deep/nested/path/file.md", "line": 5}
	got := transformEvidence(ev, true, false)
	if got["file"] != "file.md" {
		t.Errorf("expected basename, got %v", got["file"])
	}
}

func TestTransformEvidence_NoTransform(t *testing.T) {
	ev := map[string]any{"file": "/path/file.md", "line": 5}
	got := transformEvidence(ev, false, false)
	if got["file"] != "/path/file.md" {
		t.Errorf("expected full path, got %v", got["file"])
	}
}

func TestTransformEvidence_NilEvidence(t *testing.T) {
	got := transformEvidence(nil, true, false)
	if got != nil {
		t.Error("nil evidence should return nil")
	}
}

func TestTransformEvidence_EmptyFilePath(t *testing.T) {
	ev := map[string]any{"file": "", "line": 5}
	got := transformEvidence(ev, true, false)
	// Empty string filepath.Base = "."
	_ = got // just verify no panic
}

func TestBuildFindings_Empty(t *testing.T) {
	got := buildFindings(nil, false, false)
	if len(got) != 0 {
		t.Errorf("expected 0 findings, got %d", len(got))
	}
}

func TestUpload_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // slow server
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := doUpload(ctx, srv.URL, "tok", nil, false, false, sampleMeta, "", "")
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestPullConfig_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := doPullConfig(ctx, srv.URL, "tok", filepath.Join(t.TempDir(), "out.yml"))
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestValidateHTTPS_Schemes(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"https://api.example.com", false},
		{"http://api.example.com", true},
		{"ftp://api.example.com", true},
		{"://bad", true},
		{"", true},
	}
	for _, c := range cases {
		err := validateHTTPS(c.url)
		if (err != nil) != c.wantErr {
			t.Errorf("validateHTTPS(%q): err=%v, wantErr=%v", c.url, err, c.wantErr)
		}
	}
}
```

- [ ] **Step 4: Run tests and check coverage**

```bash
go test ./pkg/upload/ -v -race -count=1 -coverprofile=/tmp/upload.out
go tool cover -func=/tmp/upload.out
```

- [ ] **Step 5: Run /simplify**

- [ ] **Step 6: Commit**

```bash
git add pkg/upload/
git commit -m "harden: upload package — response limits, coverage >80%, payload safety"
```

---

### Task 13: pathutil Package — Quick Audit

**Files:**
- Modify: `pkg/pathutil/glob_test.go` (edge cases only)

- [ ] **Step 1: Audit and add edge case tests**

```go
func TestMatchGlob_PathTraversal(t *testing.T) {
	// Ensure .. patterns don't match in unexpected ways
	if MatchGlob("**/*.md", "../secret.md") {
		t.Error("path traversal should not match glob")
	}
}

func TestMatchGlob_VeryLongPath(t *testing.T) {
	path := strings.Repeat("a/", 1000) + "file.md"
	// Should not panic or hang
	_ = MatchGlob("**/*.md", path)
}
```

- [ ] **Step 2: Run tests**

```bash
go test ./pkg/pathutil/ -v -race -count=1
```

- [ ] **Step 3: Run /simplify**

- [ ] **Step 4: Commit**

```bash
git add pkg/pathutil/
git commit -m "harden: pathutil package — edge case tests"
```

---

### Task 14: CLI (main.go) — Version String & Hardening

**Files:**
- Modify: `cmd/bouncerfox/main.go`
- Modify: `.goreleaser.yml`

- [ ] **Step 1: Verify version string ldflags (already configured)**

`.goreleaser.yml` already has `ldflags: -s -w -X main.version={{.Version}}` (line 10-11).
`cmd/bouncerfox/main.go` already has `var version = "dev"` (line 34).

Verify this works end-to-end:

```bash
go build -ldflags="-X main.version=test-1.0.0" -o /tmp/bf ./cmd/bouncerfox
/tmp/bf --version
```

Expected output should include `test-1.0.0`. If not, debug the ldflags wiring.

- [ ] **Step 2: Update CI build to inject version**

In `.github/workflows/ci.yml`, update the build step:

```yaml
      - name: Build smoke test
        run: go build -ldflags="-X main.version=ci-$(git rev-parse --short HEAD)" -o bf ./cmd/bouncerfox
```

- [ ] **Step 3: Audit main.go for remaining hardening**

Read `cmd/bouncerfox/main.go`. Check:
- `filepath.Walk` vs `filepath.WalkDir` — `WalkDir` is more efficient (no `os.Stat` per entry)
- Is the file count incremented correctly? (Currently at line 183 after parsing, should be before `IsGovernedFile` check)
- Does the symlink check handle circular symlinks? (`filepath.EvalSymlinks` will error on loops — verify)
- Is `os.Exit(1)` bypassing defer cleanup?
- Is the `--config` flag using the dir correctly for config discovery?
- Verify no sensitive env vars (BOUNCERFOX_API_KEY, GITHUB_TOKEN) are ever logged or printed in error messages
- TOCTOU between file size check (line 156) and ReadFile (line 173): accepted risk for local CLI tool, but add a comment documenting it

- [ ] **Step 4: Switch to WalkDir for efficiency**

Replace `filepath.Walk` with `filepath.WalkDir` for ~30% faster file discovery:

```go
err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if walkErr != nil {
		return walkErr
	}
	if d.IsDir() {
		if d.Name() == ".git" {
			return filepath.SkipDir
		}
		return nil
	}
	if fileCount >= maxFileCount {
		fmt.Fprintf(os.Stderr, "warning: file limit (%d) reached; stopping scan\n", maxFileCount)
		return errStopWalk
	}
	// Get FileInfo only when needed (after initial checks)
	info, err := d.Info()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not stat %s: %v\n", path, err)
		return nil
	}
	// ... rest of logic unchanged
```

- [ ] **Step 5: Fix fileCount increment position**

Move `fileCount++` to before parsing, not after, so file count reflects total files encountered:

```go
fileCount++  // count before parsing
if !parser.IsGovernedFile(path) {
	return nil
}
```

- [ ] **Step 6: Run /simplify**

- [ ] **Step 7: Build and smoke test**

```bash
go build -ldflags="-X main.version=test-1.0.0" -o /tmp/bf ./cmd/bouncerfox
/tmp/bf --version
/tmp/bf scan testdata/
```

Expected: version output shows `test-1.0.0`.

- [ ] **Step 8: Commit**

```bash
git add cmd/bouncerfox/main.go .goreleaser.yml .github/workflows/ci.yml
git commit -m "harden: CLI — version ldflags, WalkDir, fileCount fix"
```

---

### Task 15: Full Test Suite & Final Lint Pass

**Files:**
- All files modified in previous tasks

- [ ] **Step 1: Run full test suite with race detector**

```bash
go test ./... -race -count=1 -coverprofile=/tmp/final.out
```

All tests must pass.

- [ ] **Step 2: Check final coverage**

```bash
go tool cover -func=/tmp/final.out | grep -E "total:|[0-5][0-9]\.[0-9]%"
```

All packages should be >80%. Fix any that aren't.

- [ ] **Step 3: Run golangci-lint**

```bash
golangci-lint run ./...
```

All issues must be fixed.

- [ ] **Step 4: Run /simplify on the entire codebase**

Final /simplify pass.

- [ ] **Step 5: Build binary and smoke test all subcommands**

```bash
go build -o /tmp/bf ./cmd/bouncerfox
/tmp/bf --version
/tmp/bf rules
/tmp/bf scan testdata/
/tmp/bf scan --format json testdata/ | python3 -m json.tool > /dev/null
/tmp/bf scan --format sarif testdata/ | python3 -m json.tool > /dev/null
/tmp/bf init && rm .bouncerfox.yml
```

- [ ] **Step 6: Commit any remaining fixes**

```bash
git add -A
git commit -m "chore: final lint pass, coverage fixes"
```

---

### Task 16: Architecture Review — Consolidated Assessment

**Files:**
- Create: `docs/architecture-review.md`

- [ ] **Step 1: Write architecture review document**

Based on all findings from Tasks 1-15, write a consolidated architecture review at `docs/architecture-review.md` covering:

**As software architect:**

1. **Package boundaries** — Are they clean? Can a new rule be added by touching only `pkg/rules/`?
2. **Rule registration ergonomics** — How easy is it to add rule 33? What files must be touched?
3. **Custom rule extensibility** — Can primitive 20 be added without restructuring?
4. **Engine pluggability** — Could rule execution be parallelized? Streamed? Made incremental?
5. **Library usability** — Can the scanner be imported as a Go library? What's the public API surface?
6. **File sizes** — Are any files too large? (sec.go at 785 lines, compiler.go at 855 lines)
7. **Global state** — `rules.RuleParams` mutation is the biggest smell. Propose fix.
8. **Coupling** — Are there any circular or surprising dependencies?
9. **Testability** — Can packages be tested in isolation?
10. **Error handling consistency** — Some functions return errors, some log to stderr, some set parse error flags. Is this intentional or inconsistent?
11. **Context propagation** — `engine.Scan()` does not accept a context; timeout only covers file discovery, not rule execution. Is this a scalability concern?
12. **Concurrency model** — Design spec mentions parallel scanning but implementation is sequential. Assess if architecture supports planned parallel scanning.

**As security engineer:**

1. **Trust boundaries** — Clear map of what's trusted vs untrusted at each layer
2. **Input validation** — Coverage at every boundary (files, config, API responses, custom rules)
3. **Resource exhaustion** — All vectors identified and mitigated
4. **Information leakage** — Secrets never in logs, errors, or uploads
5. **Regex safety** — RE2 throughout, with size limits on user-provided patterns
6. **YAML safety** — Anchors/aliases blocked, size limits enforced
7. **Fail-safe defaults** — Does the scanner fail open or closed?
8. **Dependency supply chain** — Minimal deps, all well-known

**Recommendations ranked by impact:**

1. CRITICAL fixes (must do before v1.0)
2. HIGH improvements (should do)
3. MEDIUM improvements (nice to have)
4. LOW improvements (future consideration)

- [ ] **Step 2: Run /simplify on the review document**

- [ ] **Step 3: Commit**

```bash
git add docs/architecture-review.md
git commit -m "docs: add architecture and security review"
```

---

## Summary

| Task | Package | Key Deliverables |
|------|---------|-----------------|
| 1 | Repo hygiene | .gitignore, CI fix, golangci-lint, Dockerfile |
| 2 | document | String(), unknown severity tests |
| 3 | parser | Adversarial tests (YAML, JSON, UTF-8, path traversal) |
| 4 | entropy | Edge case tests (long lines, empty, max entropy) |
| 5 | fingerprint | Collision resistance tests |
| 6 | rules | Full audit, adversarial SEC tests, boundary tests |
| 7 | custom | Depth limits, regex limits, coverage >80% |
| 8 | engine | Nil safety, suppression chain, global state warning |
| 9 | config | Malicious config tests, edge cases |
| 10 | output | JSON/SARIF/table tests, special chars |
| 11 | github | Response limits, coverage >80%, token safety |
| 12 | upload | Response limits, coverage >80%, payload safety |
| 13 | pathutil | Edge case tests |
| 14 | CLI | Version ldflags, WalkDir, fileCount fix |
| 15 | All | Final test suite, lint, smoke test |
| 16 | Docs | Architecture + security review |

**Total: 16 tasks, estimated ~80 steps**
