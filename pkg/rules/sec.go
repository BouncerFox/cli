package rules

import (
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/bouncerfox/cli/pkg/document"
	"github.com/bouncerfox/cli/pkg/entropy"
	"github.com/bouncerfox/cli/pkg/parser"
)

// sec001LinesKey is the doc.Parsed key where CheckSEC001 caches its matched
// line numbers so that downstream rules (SEC_006, SEC_018) can skip them.
const sec001LinesKey = "_sec001_lines"

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-ant-api03-[a-zA-Z0-9_-]{90,}`),
	regexp.MustCompile(`(sk|pk)_(live|test)_[a-zA-Z0-9]{24,}`),
	regexp.MustCompile(`xox[baprs]-[a-zA-Z0-9-]{10,}`),
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
	regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+`),
	regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|auth)\s*[:=]\s*['"]?[0-9a-f]{32,}`),
	regexp.MustCompile(`sk-[a-zA-Z0-9_-]{32,}`),
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`gh[su]_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`hf_[a-zA-Z0-9]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`-{5}BEGIN\s+(RSA\s+|EC\s+)?PRIVATE\s+KEY-{5}`),
	regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key)\s*[:=]\s*['"]?\S{8,}`),
}

var zeroWidthRe = regexp.MustCompile(
	"[\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e" +
		"\u200b\u200c\u200d\u200e\u200f" +
		"\u202a\u202b\u202c\u202d\u202e" +
		"\u2060\u2061\u2062\u2063\u2064" +
		"\u2066\u2067\u2068\u2069" +
		"\u206a\u206b\u206c\u206d\u206e\u206f" +
		"\ufeff\ufff9\ufffa\ufffb]",
)

var base64BlobRe = regexp.MustCompile(`[a-zA-Z0-9+/]{40,}={0,2}`)

var externalURLRe = regexp.MustCompile(`(?i)https?://[^\s"')\]]+`)

var dataURIRe = regexp.MustCompile(`(?i)data:[a-zA-Z]+/[a-zA-Z]+[;,]`)

var destructiveCmdRe = regexp.MustCompile(`(?i)\b(rm\s+-rf|rmdir|unlink|os\.remove|shutil\.rmtree|fs\.unlinkSync)\b`)

var versionPinRe = regexp.MustCompile(`\d+(\.\d+)*$`)

var reverseShellPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bnc\b[^\n]{0,500}-[elp]`),
	regexp.MustCompile(`(?i)bash\s+-i\s+>&\s*/dev/tcp/`),
	regexp.MustCompile(`(?i)/dev/tcp/`),
	regexp.MustCompile(`(?i)\bmkfifo\b[^\n]{0,500}\bnc\b`),
	regexp.MustCompile(`(?i)python[^\n]{0,500}socket[^\n]{0,500}connect`),
	regexp.MustCompile(`(?i)\bsocat\b[^\n]{0,500}\bexec\b`),
	regexp.MustCompile(`(?i)perl\s[^\n]{0,500}-e\s[^\n]{0,500}socket`),
	regexp.MustCompile(`(?i)ruby\s[^\n]{0,500}-e\s[^\n]{0,500}socket`),
	regexp.MustCompile(`(?i)\bexec\b\s+\d+<>/dev/tcp/`),
	regexp.MustCompile(`(?i)php\s[^\n]{0,500}fsockopen`),
	regexp.MustCompile(`(?i)\bncat\b[^\n]{0,500}-[elp]`),
	regexp.MustCompile(`(?i)powershell.*-e(nc(odedcommand)?)?`),
	regexp.MustCompile(`(?i)node\s+-e[^\n]{0,500}child_process`),
	regexp.MustCompile(`(?i)node\s+-e[^\n]{0,500}net\.Socket`),
}

var downloadExecPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)curl\s+[^\n]{0,500}\|\s*(ba)?sh`),
	regexp.MustCompile(`(?i)wget\s+[^\n]{0,500}\|\s*(ba)?sh`),
	regexp.MustCompile(`(?i)curl\s+[^\n]{0,500}-o\s+\S+\s*&&\s*(ba)?sh`),
	regexp.MustCompile(`(?i)wget\s+[^\n]{0,500}-O\s+\S+\s*&&\s*(ba)?sh`),
	regexp.MustCompile(`(?i)eval\s+[^\n]{0,500}\$\(curl`),
	regexp.MustCompile(`(?i)eval\s+[^\n]{0,500}\$\(wget`),
	regexp.MustCompile(`(?i)\bsource\s+<\(curl`),
	regexp.MustCompile(`(?i)python3?\s+[^\n]{0,500}-c\s+[^\n]{0,500}urllib`),
}

var envExfiltrationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(echo|cat|printenv)\s+[^\n]{0,500}\$\{?(HOME|PATH|ANTHROPIC_API_KEY|API_KEY|SECRET|TOKEN|PASSWORD)`),
	regexp.MustCompile(`(?i)env\s*\|`),
	regexp.MustCompile(`(?i)curl\s+[^\n]{0,500}\$\{?(ANTHROPIC_API_KEY|API_KEY|SECRET|TOKEN)`),
	regexp.MustCompile(`(?i)wget\s+[^\n]{0,500}\$\{?(ANTHROPIC_API_KEY|API_KEY|SECRET|TOKEN)`),
	regexp.MustCompile(`(?i)/proc/self/environ`),
	regexp.MustCompile(`(?i)\bset\s*\|`),
	regexp.MustCompile(`(?i)\bcompgen\s+-v`),
}

var dangerousEnvVars = map[string]bool{
	"HTTP_PROXY":            true,
	"HTTPS_PROXY":           true,
	"ALL_PROXY":             true,
	"NODE_EXTRA_CA_CERTS":   true,
	"SSL_CERT_FILE":         true,
	"PYTHONPATH":            true,
	"NODE_PATH":             true,
	"LD_PRELOAD":            true,
	"DYLD_INSERT_LIBRARIES": true,
	"REQUESTS_CA_BUNDLE":    true,
	"CURL_CA_BUNDLE":        true,
	"GIT_SSH_COMMAND":       true,
	"NPM_CONFIG_REGISTRY":   true,
	"PIP_INDEX_URL":         true,
	"PIP_EXTRA_INDEX_URL":   true,
}

// CheckSEC019 detects YAML anchor/alias usage (potential YAML bomb).
func CheckSEC019(doc *document.ConfigDocument) []document.ScanFinding {
	if !hasParseError(doc) {
		return nil
	}
	reason, _ := doc.Parsed["_reason"].(string)
	if reason != "yaml_anchors" {
		return nil
	}
	line := 1
	if rl, ok := doc.Parsed["_rejection_line"].(int); ok {
		line = rl
	}
	return []document.ScanFinding{{
		RuleID:   "SEC_019",
		Severity: document.SeverityHigh,
		Message:  "YAML anchor/alias detected — potential YAML bomb",
		Evidence: map[string]any{
			"file":    doc.FilePath,
			"line":    line,
			"snippet": "",
		},
		Remediation: "Remove YAML anchors (&) and aliases (*) from frontmatter.",
	}}
}

// CheckSEC020 detects deeply nested JSON that may cause resource exhaustion.
func CheckSEC020(doc *document.ConfigDocument) []document.ScanFinding {
	if !hasParseError(doc) {
		return nil
	}
	reason, _ := doc.Parsed["_reason"].(string)
	if reason != "json_nesting_depth" {
		return nil
	}
	return []document.ScanFinding{{
		RuleID:   "SEC_020",
		Severity: document.SeverityHigh,
		Message:  "JSON nesting exceeds maximum depth — possible resource exhaustion",
		Evidence: map[string]any{
			"file":    doc.FilePath,
			"line":    1,
			"snippet": "",
		},
		Remediation: "Reduce JSON nesting depth to 10 levels or fewer.",
	}}
}

func getURLAllowlist() []string {
	if p, ok := RuleParams["SEC_002"]; ok {
		if al, ok := p["url_allowlist"].([]string); ok {
			return al
		}
	}
	return nil
}

// checkHookPatterns matches hook commands against regex patterns, returning findings.
func checkHookPatterns(
	doc *document.ConfigDocument,
	patterns []*regexp.Regexp,
	ruleID string,
	severity document.FindingSeverity,
	messageFmt, remediation string,
) []document.ScanFinding {
	var findings []document.ScanFinding
	for _, hc := range ExtractHookCommands(doc.Parsed) {
		for _, pat := range patterns {
			if pat.MatchString(hc.Command) {
				findings = append(findings, document.ScanFinding{
					RuleID:   ruleID,
					Severity: severity,
					Message:  fmt.Sprintf(messageFmt, hc.Name),
					Evidence: map[string]any{
						"file":    doc.FilePath,
						"line":    parser.FindJSONKeyLine(doc.Content, hc.Name),
						"snippet": truncSnippet(hc.Command, 100),
					},
					Remediation: remediation,
				})
				break
			}
		}
	}
	return findings
}

// CheckSEC001 detects hardcoded secret-like tokens.
// Iterates ALL lines (including code blocks). Evidence snippet is always "".
// Caches matched line numbers in doc.Parsed[sec001LinesKey].
func CheckSEC001(doc *document.ConfigDocument) []document.ScanFinding {
	lines := strings.Split(doc.Content, "\n")
	sec001Lines := make(map[int]bool)
	var findings []document.ScanFinding

	for i, line := range lines {
		lineNum := i + 1
		if len(line) > maxLineLength {
			line = line[:maxLineLength]
		}
		for _, pat := range secretPatterns {
			if pat.MatchString(line) {
				sec001Lines[lineNum] = true
				findings = append(findings, document.ScanFinding{
					RuleID:   "SEC_001",
					Severity: document.SeverityCritical,
					Message:  "Secret-like token pattern detected",
					Evidence: map[string]any{
						"file":    doc.FilePath,
						"line":    lineNum,
						"snippet": "",
					},
					Remediation: "Remove hardcoded secrets and use environment variables or a secret manager.",
				})
				break
			}
		}
	}

	doc.Parsed[sec001LinesKey] = sec001Lines
	return findings
}

// CheckSEC002 detects external URLs not in the allowlist. Skips code blocks.
func CheckSEC002(doc *document.ConfigDocument) []document.ScanFinding {
	lines := strings.Split(doc.Content, "\n")
	cbl := getParsedIntBoolMap(doc, "content_code_block_lines")
	allowlist := getURLAllowlist()
	var findings []document.ScanFinding

	for i, line := range lines {
		lineNum := i + 1
		if cbl[lineNum] {
			continue
		}
		if len(line) > maxLineLength {
			line = line[:maxLineLength]
		}
		m := externalURLRe.FindString(line)
		if m == "" {
			continue
		}
		if URLMatchesAllowlist(m, allowlist) {
			continue
		}
		findings = append(findings, document.ScanFinding{
			RuleID:   "SEC_002",
			Severity: document.SeverityHigh,
			Message:  "External URL found that may not be in the org allowlist",
			Evidence: map[string]any{
				"file":    doc.FilePath,
				"line":    lineNum,
				"snippet": m,
				"url":     m,
			},
			Remediation: "Verify this URL is in the organization's allowlist, or remove it.",
		})
	}
	return findings
}

// CheckSEC003 detects destructive commands in skill_md files. Skips code blocks.
func CheckSEC003(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeSkillMD {
		return nil
	}
	return CheckLinePatterns(
		strings.Split(doc.Content, "\n"),
		[]*regexp.Regexp{destructiveCmdRe},
		doc, "SEC_003", document.SeverityHigh,
		"File deletion or destructive command found",
		"Remove destructive file operations from skill definitions.",
		getParsedIntBoolMap(doc, "content_code_block_lines"), 0,
	)
}

// CheckSEC004 detects invisible unicode / zero-width characters. Does NOT skip code blocks.
func CheckSEC004(doc *document.ConfigDocument) []document.ScanFinding {
	lines := strings.Split(doc.Content, "\n")
	var findings []document.ScanFinding

	for i, line := range lines {
		lineNum := i + 1
		if len(line) > maxLineLength {
			line = line[:maxLineLength]
		}
		if zeroWidthRe.MatchString(line) {
			findings = append(findings, document.ScanFinding{
				RuleID:   "SEC_004",
				Severity: document.SeverityHigh,
				Message:  "Zero-width or invisible character detected",
				Evidence: map[string]any{
					"file":    doc.FilePath,
					"line":    lineNum,
					"snippet": "",
				},
				Remediation: "Remove invisible unicode characters that could be used for instruction smuggling.",
			})
		}
	}
	return findings
}

// CheckSEC006 detects base64-encoded blobs. Skips code blocks and lines already
// flagged by SEC_001.
func CheckSEC006(doc *document.ConfigDocument) []document.ScanFinding {
	lines := strings.Split(doc.Content, "\n")
	cbl := getParsedIntBoolMap(doc, "content_code_block_lines")
	sec001Lines := getParsedIntBoolMap(doc, sec001LinesKey)
	var findings []document.ScanFinding

	for i, line := range lines {
		lineNum := i + 1
		if cbl[lineNum] {
			continue
		}
		if sec001Lines[lineNum] {
			continue
		}
		if len(line) > maxLineLength {
			line = line[:maxLineLength]
		}
		if m := base64BlobRe.FindString(line); m != "" {
			findings = append(findings, document.ScanFinding{
				RuleID:   "SEC_006",
				Severity: document.SeverityWarn,
				Message:  "Base64-encoded blob detected (possible encoded payload)",
				Evidence: map[string]any{
					"file":            doc.FilePath,
					"line":            lineNum,
					"snippet":         "",
					"measured_length": len(m),
				},
				Remediation: "Review the base64-encoded content to ensure it does not contain secrets or malicious payloads.",
			})
		}
	}
	return findings
}

// CheckSEC007 detects data: URIs. Skips code blocks.
func CheckSEC007(doc *document.ConfigDocument) []document.ScanFinding {
	return CheckLinePatterns(
		strings.Split(doc.Content, "\n"),
		[]*regexp.Regexp{dataURIRe},
		doc, "SEC_007", document.SeverityHigh,
		"data: URI detected (possible encoded payload)",
		"Remove data: URIs — they can embed malicious payloads.",
		getParsedIntBoolMap(doc, "content_code_block_lines"), 0,
	)
}

// CheckSEC009 detects reverse shell patterns in settings_json hook commands.
func CheckSEC009(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeSettingsJSON || hasParseError(doc) {
		return nil
	}
	return checkHookPatterns(doc, reverseShellPatterns, "SEC_009", document.SeverityCritical,
		"Hook '%s' contains reverse shell pattern", "Remove reverse shell commands from hooks.")
}

// CheckSEC010 detects credential exfiltration patterns in settings_json hook commands.
func CheckSEC010(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeSettingsJSON || hasParseError(doc) {
		return nil
	}
	return checkHookPatterns(doc, envExfiltrationPatterns, "SEC_010", document.SeverityCritical,
		"Hook '%s' exfiltrates environment variables or credentials", "Remove credential exfiltration from hooks.")
}

// CheckSEC011 detects download-and-execute patterns in settings_json hooks and mcp_json servers.
func CheckSEC011(doc *document.ConfigDocument) []document.ScanFinding {
	if hasParseError(doc) {
		return nil
	}

	switch doc.FileType {
	case document.FileTypeSettingsJSON:
		return checkHookPatterns(doc, downloadExecPatterns, "SEC_011", document.SeverityCritical,
			"Hook '%s' downloads and executes remote content", "Do not download and execute remote code in hooks.")

	case document.FileTypeMCPJSON:
		var findings []document.ScanFinding
		for _, srv := range IterMCPServers(doc.Parsed) {
			fullCmd := BuildMCPCommand(srv.Config)
			for _, pat := range downloadExecPatterns {
				if pat.MatchString(fullCmd) {
					findings = append(findings, document.ScanFinding{
						RuleID:   "SEC_011",
						Severity: document.SeverityCritical,
						Message:  fmt.Sprintf("MCP server '%s' downloads and executes remote content", srv.Name),
						Evidence: map[string]any{
							"file":    doc.FilePath,
							"line":    parser.FindJSONKeyLine(doc.Content, srv.Name),
							"snippet": truncSnippet(fullCmd, 100),
						},
						Remediation: "Do not download and execute remote code in MCP server commands.",
					})
					break
				}
			}
		}
		return findings
	}

	return nil
}

// CheckSEC012 detects dangerous environment variable overrides in settings_json.
func CheckSEC012(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeSettingsJSON || hasParseError(doc) {
		return nil
	}

	envBlock, ok := doc.Parsed["env"].(map[string]any)
	if !ok {
		return nil
	}

	var findings []document.ScanFinding
	for envKey, envVal := range envBlock {
		if dangerousEnvVars[strings.ToUpper(envKey)] {
			valStr := truncSnippet(fmt.Sprintf("%v", envVal), 80)
			findings = append(findings, document.ScanFinding{
				RuleID:   "SEC_012",
				Severity: document.SeverityHigh,
				Message:  fmt.Sprintf("Dangerous env var '%s' set (proxy/path/library injection)", envKey),
				Evidence: map[string]any{
					"file":    doc.FilePath,
					"line":    parser.FindJSONKeyLine(doc.Content, envKey),
					"snippet": envKey + "=" + valStr,
				},
				Remediation: "Remove dangerous environment variable overrides.",
			})
		}
	}
	return findings
}

// CheckSEC014 detects unpinned MCP package versions in mcp_json.
func CheckSEC014(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeMCPJSON || hasParseError(doc) {
		return nil
	}

	var findings []document.ScanFinding
	for _, srv := range IterMCPServers(doc.Parsed) {
		command, _ := srv.Config["command"].(string)
		if command != "npx" && command != "bunx" && command != "uvx" && command != "pipx" {
			continue
		}

		args, _ := srv.Config["args"].([]any)
		if len(args) == 0 {
			continue
		}

		fullCmd := BuildMCPCommand(srv.Config)
		hasVersionPin := strings.Contains(fullCmd, "--version")
		for _, arg := range args {
			argStr := asString(arg)
			if idx := strings.LastIndex(argStr, "@"); idx >= 0 {
				if versionPinRe.MatchString(argStr[idx+1:]) {
					hasVersionPin = true
					break
				}
			}
		}

		if !hasVersionPin {
			findings = append(findings, document.ScanFinding{
				RuleID:   "SEC_014",
				Severity: document.SeverityHigh,
				Message:  fmt.Sprintf("MCP server '%s' uses unpinned package version", srv.Name),
				Evidence: map[string]any{
					"file":    doc.FilePath,
					"line":    parser.FindJSONKeyLine(doc.Content, srv.Name),
					"snippet": truncSnippet(fullCmd, 100),
				},
				Remediation: "Pin the package version (e.g., package@1.2.3).",
			})
		}
	}
	return findings
}

// CheckSEC016 detects plain HTTP URLs for MCP servers (excluding localhost).
func CheckSEC016(doc *document.ConfigDocument) []document.ScanFinding {
	if doc.FileType != document.FileTypeMCPJSON || hasParseError(doc) {
		return nil
	}

	var findings []document.ScanFinding
	for _, srv := range IterMCPServers(doc.Parsed) {
		u, ok := srv.Config["url"].(string)
		if !ok {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(u), "http://") {
			continue
		}
		parsed, err := url.Parse(u)
		if err == nil {
			hostname := strings.ToLower(parsed.Hostname())
			if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
				continue
			}
		}
		findings = append(findings, document.ScanFinding{
			RuleID:   "SEC_016",
			Severity: document.SeverityHigh,
			Message:  fmt.Sprintf("MCP server '%s' uses plain HTTP instead of HTTPS", srv.Name),
			Evidence: map[string]any{
				"file":    doc.FilePath,
				"line":    parser.FindJSONKeyLine(doc.Content, srv.Name),
				"snippet": truncSnippet(u, 100),
			},
			Remediation: "Use HTTPS for MCP server URLs.",
		})
	}
	return findings
}

// sec018Params returns the entropy thresholds and min lengths for SEC_018.
// Reads from RuleParams["SEC_018"] with safe defaults.
func sec018Params() (thresholds map[string]map[string]float64, minLengths map[string]int) {
	p := RuleParams["SEC_018"]
	getFloat := func(key string, def float64) float64 {
		if v, ok := p[key]; ok {
			switch n := v.(type) {
			case float64:
				return n
			case int:
				return float64(n)
			}
		}
		return def
	}
	getInt := func(key string, def int) int {
		if v, ok := p[key]; ok {
			switch n := v.(type) {
			case int:
				return n
			case float64:
				return int(n)
			}
		}
		return def
	}
	thresholds = map[string]map[string]float64{
		"credential": {
			"hex":    getFloat("hex_threshold_credential", 3.0),
			"base64": getFloat("base64_threshold_credential", 4.0),
			"mixed":  getFloat("mixed_threshold_credential", 4.5),
		},
		"freetext": {
			"hex":    getFloat("hex_threshold_freetext", 3.5),
			"base64": getFloat("base64_threshold_freetext", 4.5),
			"mixed":  getFloat("mixed_threshold_freetext", 5.0),
		},
	}
	minLengths = map[string]int{
		"credential": getInt("min_length_credential", 16),
		"freetext":   getInt("min_length_freetext", 32),
	}
	return
}

// passesEntropyThreshold returns whether the candidate exceeds the threshold,
// along with its entropy value and charset.
func passesEntropyThreshold(candidate, context string, thresholds map[string]map[string]float64) (passes bool, ent float64, charset string) {
	charset = entropy.ClassifyCharset(candidate)
	ent = entropy.ShannonEntropy(candidate)
	contextThresholds, ok := thresholds[context]
	if !ok {
		contextThresholds = thresholds["freetext"]
	}
	threshold, ok := contextThresholds[charset]
	if !ok {
		threshold = 5.0
	}
	return ent >= threshold, ent, charset
}

const sec018Remediation = "If this is a secret, remove it and use environment variables or a secret manager. If it is a hash or identifier, it can be safely ignored."

// CheckSEC018 detects high-entropy strings that may be hardcoded secrets.
// For markdown files it scans content lines (skipping code blocks and SEC_001 lines).
// For JSON files it walks the parsed document recursively.
func CheckSEC018(doc *document.ConfigDocument) []document.ScanFinding {
	switch doc.FileType {
	case document.FileTypeSkillMD, document.FileTypeClaudeMD, document.FileTypeAgentMD:
		return checkSEC018Markdown(doc)
	case document.FileTypeSettingsJSON, document.FileTypeMCPJSON:
		return checkSEC018JSON(doc)
	}
	return nil
}

func checkSEC018Markdown(doc *document.ConfigDocument) []document.ScanFinding {
	thresholds, minLengths := sec018Params()

	contentLines := strings.Split(doc.Content, "\n")
	sec001Lines := getParsedIntBoolMap(doc, sec001LinesKey)

	// code_block_lines is body-relative (1-based); body_start_line tells us
	// the offset of the body within the full file.
	codeBlockLines := getParsedIntBoolMap(doc, "code_block_lines")
	bodyStartLine := 1
	if bsl, ok := doc.Parsed["body_start_line"].(int); ok {
		bodyStartLine = bsl
	}

	var findings []document.ScanFinding
	for i, line := range contentLines {
		lineNum := i + 1

		// Translate content line number to body-relative for code block check.
		bodyLineNum := lineNum - (bodyStartLine - 1)
		if codeBlockLines[bodyLineNum] {
			continue
		}
		if sec001Lines[lineNum] {
			continue
		}
		if len(line) > maxLineLength {
			line = line[:maxLineLength]
		}

		ctx := entropy.DetectContext(line)
		minLen := minLengths[ctx]

		// Collect candidates: whole line + value portions in credential context.
		var candidateSegments []string
		candidateSegments = append(candidateSegments, entropy.ExtractCandidates(line, minLen)...)
		if ctx == "credential" {
			for _, sep := range []string{"=", ":"} {
				if idx := strings.Index(line, sep); idx >= 0 {
					valuePart := strings.TrimSpace(line[idx+1:])
					valuePart = strings.Trim(valuePart, `'"`)
					candidateSegments = append(candidateSegments, entropy.ExtractCandidates(valuePart, minLen)...)
				}
			}
		}

		for _, candidate := range candidateSegments {
			passes, ent, charset := passesEntropyThreshold(candidate, ctx, thresholds)
			if passes {
				findings = append(findings, document.ScanFinding{
					RuleID:   "SEC_018",
					Severity: document.SeverityHigh,
					Message:  "High-entropy string detected — possible hardcoded secret",
					Evidence: map[string]any{
						"file":             doc.FilePath,
						"line":             lineNum,
						"snippet":          "",
						"detection_method": "entropy",
						"context":          ctx,
						"entropy":          math.Round(ent*100) / 100,
						"charset":          charset,
						"candidate_length": len(candidate),
					},
					Remediation: sec018Remediation,
				})
				break // one finding per line
			}
		}
	}
	return findings
}

type jsonEntry struct {
	key, dotPath, value string
}

func walkJSON(obj any, path string, depth int) []jsonEntry {
	if depth > 10 {
		return nil
	}
	var results []jsonEntry
	switch v := obj.(type) {
	case map[string]any:
		for k, child := range v {
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			results = append(results, walkJSON(child, childPath, depth+1)...)
		}
	case []any:
		for i, item := range v {
			results = append(results, walkJSON(item, fmt.Sprintf("%s[%d]", path, i), depth+1)...)
		}
	case string:
		key := path
		if idx := strings.LastIndex(path, "."); idx >= 0 {
			key = path[idx+1:]
		}
		key = arrayIndexRe.ReplaceAllString(key, "")
		results = append(results, jsonEntry{key, path, v})
	}
	return results
}

// findLineForValue returns the 1-based line number where value first appears in content.
func findLineForValue(content, value string) int {
	for i, line := range strings.Split(content, "\n") {
		if strings.Contains(line, value) {
			return i + 1
		}
	}
	return 1
}

var arrayIndexRe = regexp.MustCompile(`\[\d+\]`)

func checkSEC018JSON(doc *document.ConfigDocument) []document.ScanFinding {
	if hasParseError(doc) {
		return nil
	}

	thresholds, minLengths := sec018Params()
	entries := walkJSON(doc.Parsed, "", 0)

	var findings []document.ScanFinding
	for _, entry := range entries {
		// Skip values already matched by any SEC_001 pattern.
		alreadyMatched := false
		for _, pat := range secretPatterns {
			if pat.MatchString(entry.value) {
				alreadyMatched = true
				break
			}
		}
		if alreadyMatched {
			continue
		}

		// Determine context.
		ctx := "freetext"
		if entropy.CredentialKeyRe.MatchString(entry.key) ||
			strings.Contains(entry.dotPath, ".env.") ||
			strings.HasSuffix(entry.dotPath, ".env") {
			ctx = "credential"
		}

		minLen := minLengths[ctx]
		candidates := entropy.ExtractCandidates(entry.value, minLen)
		for _, candidate := range candidates {
			passes, ent, charset := passesEntropyThreshold(candidate, ctx, thresholds)
			if passes {
				lineNum := findLineForValue(doc.Content, candidate)
				findings = append(findings, document.ScanFinding{
					RuleID:   "SEC_018",
					Severity: document.SeverityHigh,
					Message:  fmt.Sprintf("High-entropy string in %s — possible hardcoded secret", entry.dotPath),
					Evidence: map[string]any{
						"file":             doc.FilePath,
						"line":             lineNum,
						"snippet":          "",
						"detection_method": "entropy",
						"context":          ctx,
						"entropy":          math.Round(ent*100) / 100,
						"charset":          charset,
						"candidate_length": len(candidate),
					},
					Remediation: sec018Remediation,
				})
				break // one finding per JSON value
			}
		}
	}
	return findings
}
