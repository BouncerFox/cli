// Package custom compiles declarative YAML match configs into Go check function closures.
// No eval, no exec, no dynamic code generation — only pre-compiled closures.
package custom

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bouncerfox/cli/pkg/document"
)

// collectionIterationLimit caps the number of items visited in collection_any / collection_none.
const collectionIterationLimit = 1000

// maxMatchNestingDepth limits recursive combinator nesting (all_of/any_of/not).
const maxMatchNestingDepth = 10

// maxRegexLength limits user-provided regex patterns to prevent resource abuse.
const maxRegexLength = 4096

// compileRegex compiles a user-provided regex with a size limit.
func compileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexLength {
		return nil, fmt.Errorf("regex pattern exceeds maximum length (%d chars)", maxRegexLength)
	}
	return regexp.Compile(pattern)
}

// CheckFn is the type of a compiled check function.
type CheckFn func(*document.ConfigDocument) []document.ScanFinding

// Compile turns a raw rule map (from YAML) into a check function closure.
// The rule map must contain at minimum: "id", "severity", and "match".
func Compile(rule map[string]any) (CheckFn, error) {
	matchRaw, ok := rule["match"]
	if !ok {
		return nil, fmt.Errorf("rule %q: missing 'match' key", strField(rule, "id"))
	}
	matchCfg, ok := matchRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("rule %q: 'match' must be a map", strField(rule, "id"))
	}

	sev, err := parseSeverity(strField(rule, "severity"))
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", strField(rule, "id"), err)
	}

	ruleID := strField(rule, "id")
	name := strField(rule, "name")
	remediation := strField(rule, "remediation")

	ctx := &ruleCtx{
		id:          ruleID,
		message:     name + " (custom rule)",
		severity:    sev,
		remediation: remediation,
	}

	return compileMatch(matchCfg, ctx)
}

// ruleCtx carries the rule metadata needed to build findings and compilation state.
type ruleCtx struct {
	depth       int // current nesting depth for recursion limits
	id          string
	message     string
	severity    document.FindingSeverity
	remediation string
}

func (rc *ruleCtx) finding(doc *document.ConfigDocument, line int, snippet string) document.ScanFinding {
	if line <= 0 {
		line = 1
	}
	return document.ScanFinding{
		RuleID:   rc.id,
		Severity: rc.severity,
		Message:  rc.message,
		Evidence: map[string]any{
			"file":    doc.FilePath,
			"line":    line,
			"snippet": snippet,
		},
		Remediation: rc.remediation,
	}
}

// ---------------------------------------------------------------------------
// Top-level match dispatcher
// ---------------------------------------------------------------------------

// compileMatch compiles an entire match config map into a CheckFn.
// The match map either contains a "type" key (new-style single primitive)
// or multiple keys that are ANDed together (legacy multi-key style).
func compileMatch(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	ctx.depth++
	defer func() { ctx.depth-- }()
	if ctx.depth > maxMatchNestingDepth {
		return nil, fmt.Errorf("match nesting exceeds maximum depth (%d)", maxMatchNestingDepth)
	}
	// New-style: single "type" key dispatches to a primitive
	if typeVal, hasType := cfg["type"]; hasType {
		typeName, _ := typeVal.(string)
		return compilePrimitive(typeName, cfg, ctx)
	}

	// Legacy: each key is a primitive name; all must produce findings (AND)
	var fns []CheckFn
	for key, val := range cfg {
		subCfg, err := toMap(val)
		if err != nil {
			// Some primitives (field_exists, field_missing, content_contains etc.)
			// take a scalar value rather than a sub-map. Wrap it.
			subCfg = map[string]any{"_value": val}
		}
		fn, err := compilePrimitive(key, subCfg, ctx)
		if err != nil {
			return nil, err
		}
		fns = append(fns, fn)
	}

	if len(fns) == 1 {
		return fns[0], nil
	}

	// AND combinator
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		var all []document.ScanFinding
		for _, fn := range fns {
			results := fn(doc)
			if len(results) == 0 {
				return nil
			}
			all = append(all, results...)
		}
		return all
	}, nil
}

// compilePrimitive dispatches by primitive type name.
func compilePrimitive(typeName string, cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	switch typeName {
	case "line_pattern":
		return compileLinePattern(cfg, ctx)
	case "line_patterns":
		return compileLinePatterns(cfg, ctx)
	case "content_contains":
		return compileContentContains(cfg, ctx)
	case "content_not_contains":
		return compileContentNotContains(cfg, ctx)
	case "field_equals":
		return compileFieldEquals(cfg, ctx)
	case "field_exists":
		return compileFieldExists(cfg, ctx)
	case "field_missing":
		return compileFieldMissing(cfg, ctx)
	case "field_in":
		return compileFieldIn(cfg, ctx)
	case "field_not_in":
		return compileFieldNotIn(cfg, ctx)
	case "field_matches":
		return compileFieldMatches(cfg, ctx)
	case "collection_any":
		return compileCollectionAny(cfg, ctx)
	case "collection_none":
		return compileCollectionNone(cfg, ctx)
	case "min_length":
		return compileMinLength(cfg, ctx)
	case "max_length":
		return compileMaxLength(cfg, ctx)
	case "max_size_bytes":
		return compileMaxSizeBytes(cfg, ctx)
	case "all_of":
		return compileAllOf(cfg, ctx)
	case "any_of":
		return compileAnyOf(cfg, ctx)
	case "not":
		return compileNot(cfg, ctx)
	case "per_file_type":
		return compilePerFileType(cfg, ctx)
	default:
		// Unknown primitive — no-op
		return func(_ *document.ConfigDocument) []document.ScanFinding { return nil }, nil
	}
}

// ---------------------------------------------------------------------------
// Pattern primitives
// ---------------------------------------------------------------------------

func compileLinePattern(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	patStr, _ := cfg["pattern"].(string)
	re, err := compileRegex(patStr)
	if err != nil {
		return nil, fmt.Errorf("line_pattern: bad pattern %q: %w", patStr, err)
	}
	skipCodeBlocks, _ := cfg["skip_code_blocks"].(bool)

	return func(doc *document.ConfigDocument) []document.ScanFinding {
		var codeBlockLines map[int]struct{}
		if skipCodeBlocks {
			codeBlockLines = extractCodeBlockLines(doc)
		}
		var findings []document.ScanFinding
		for i, line := range strings.Split(doc.Content, "\n") {
			lineNum := i + 1
			if skipCodeBlocks {
				if _, inBlock := codeBlockLines[lineNum]; inBlock {
					continue
				}
			}
			if re.MatchString(line) {
				findings = append(findings, ctx.finding(doc, lineNum, strings.TrimSpace(line)))
			}
		}
		return findings
	}, nil
}

func compileLinePatterns(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	// patterns is []any where each element is a map with "pattern" key
	patternsRaw, _ := cfg["patterns"].([]any)
	type compiled struct {
		re   *regexp.Regexp
		skip bool
	}
	var pats []compiled
	for _, item := range patternsRaw {
		m, ok := item.(map[string]any)
		if !ok {
			// plain string shorthand
			patStr, _ := item.(string)
			re, err := compileRegex(patStr)
			if err != nil {
				return nil, fmt.Errorf("line_patterns: bad pattern %q: %w", patStr, err)
			}
			pats = append(pats, compiled{re: re})
			continue
		}
		patStr, _ := m["pattern"].(string)
		re, err := compileRegex(patStr)
		if err != nil {
			return nil, fmt.Errorf("line_patterns: bad pattern %q: %w", patStr, err)
		}
		skip, _ := m["skip_code_blocks"].(bool)
		pats = append(pats, compiled{re: re, skip: skip})
	}

	return func(doc *document.ConfigDocument) []document.ScanFinding {
		codeBlockLines := extractCodeBlockLines(doc)
		var findings []document.ScanFinding
		for i, line := range strings.Split(doc.Content, "\n") {
			lineNum := i + 1
			for _, p := range pats {
				if p.skip {
					if _, inBlock := codeBlockLines[lineNum]; inBlock {
						continue
					}
				}
				if p.re.MatchString(line) {
					findings = append(findings, ctx.finding(doc, lineNum, strings.TrimSpace(line)))
					break // one finding per line
				}
			}
		}
		return findings
	}, nil
}

func compileContentContains(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	value := strFieldFromMap(cfg, "value", "_value")
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		if strings.Contains(doc.Content, value) {
			return []document.ScanFinding{ctx.finding(doc, 1, "")}
		}
		return nil
	}, nil
}

func compileContentNotContains(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	value := strFieldFromMap(cfg, "value", "_value")
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		if !strings.Contains(doc.Content, value) {
			return []document.ScanFinding{ctx.finding(doc, 1, "")}
		}
		return nil
	}, nil
}

// ---------------------------------------------------------------------------
// Field primitives
// ---------------------------------------------------------------------------

func compileFieldEquals(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	path := strFieldFromMap(cfg, "field", "path")
	expected := cfg["value"]
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		actual := resolveFieldPath(doc.Parsed, path)
		if actual == nil {
			return nil
		}
		if fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", expected) {
			return []document.ScanFinding{ctx.finding(doc, 1, "")}
		}
		return nil
	}, nil
}

func compileFieldExists(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	path := strFieldFromMap(cfg, "field", "_value")
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		v := resolveFieldPath(doc.Parsed, path)
		if isPresent(v) {
			return []document.ScanFinding{ctx.finding(doc, 1, "")}
		}
		return nil
	}, nil
}

func compileFieldMissing(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	path := strFieldFromMap(cfg, "field", "_value")
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		v := resolveFieldPath(doc.Parsed, path)
		if !isPresent(v) {
			return []document.ScanFinding{ctx.finding(doc, 1, "")}
		}
		return nil
	}, nil
}

func compileFieldIn(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	path := strFieldFromMap(cfg, "field", "path")
	valuesSet := toStringSet(cfg["values"])
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		fv := resolveFieldPath(doc.Parsed, path)
		if fv == nil {
			return nil
		}
		if lst, ok := fv.([]any); ok {
			for _, item := range lst {
				if _, in := valuesSet[fmt.Sprintf("%v", item)]; in {
					return []document.ScanFinding{ctx.finding(doc, 1, "")}
				}
			}
		} else {
			if _, in := valuesSet[fmt.Sprintf("%v", fv)]; in {
				return []document.ScanFinding{ctx.finding(doc, 1, "")}
			}
		}
		return nil
	}, nil
}

func compileFieldNotIn(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	path := strFieldFromMap(cfg, "field", "path")
	valuesSet := toStringSet(cfg["values"])
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		fv := resolveFieldPath(doc.Parsed, path)
		if fv == nil {
			return nil
		}
		if lst, ok := fv.([]any); ok {
			for _, item := range lst {
				if _, in := valuesSet[fmt.Sprintf("%v", item)]; !in {
					return []document.ScanFinding{ctx.finding(doc, 1, "")}
				}
			}
		} else {
			if _, in := valuesSet[fmt.Sprintf("%v", fv)]; !in {
				return []document.ScanFinding{ctx.finding(doc, 1, "")}
			}
		}
		return nil
	}, nil
}

func compileFieldMatches(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	path := strFieldFromMap(cfg, "field", "path")
	patStr, _ := cfg["pattern"].(string)
	re, err := compileRegex(patStr)
	if err != nil {
		return nil, fmt.Errorf("field_matches: bad pattern %q: %w", patStr, err)
	}
	negate, _ := cfg["negate"].(bool)
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		fv := resolveFieldPath(doc.Parsed, path)
		if fv == nil {
			return nil
		}
		s := fmt.Sprintf("%v", fv)
		matched := re.MatchString(s)
		if negate {
			matched = !matched
		}
		if matched {
			return []document.ScanFinding{ctx.finding(doc, 1, "")}
		}
		return nil
	}, nil
}

// ---------------------------------------------------------------------------
// Collection primitives
// ---------------------------------------------------------------------------

func compileCollectionAny(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	path := strFieldFromMap(cfg, "field", "path")
	condition, err := toMap(cfg["match"])
	if err != nil {
		// try "condition" key (Python compat)
		condition, err = toMap(cfg["condition"])
		if err != nil {
			return nil, fmt.Errorf("collection_any: missing 'match' or 'condition'")
		}
	}
	compiledRe := precompileConditionRegex(condition)

	return func(doc *document.ConfigDocument) []document.ScanFinding {
		coll := resolveFieldPath(doc.Parsed, path)
		if coll == nil {
			return nil
		}
		for _, kv := range iterateCollection(coll) {
			if evalCondition(condition, kv.val, kv.key, compiledRe) {
				return []document.ScanFinding{ctx.finding(doc, 1, "")}
			}
		}
		return nil
	}, nil
}

func compileCollectionNone(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	path := strFieldFromMap(cfg, "field", "path")
	condition, err := toMap(cfg["match"])
	if err != nil {
		condition, err = toMap(cfg["condition"])
		if err != nil {
			return nil, fmt.Errorf("collection_none: missing 'match' or 'condition'")
		}
	}
	compiledRe := precompileConditionRegex(condition)

	return func(doc *document.ConfigDocument) []document.ScanFinding {
		coll := resolveFieldPath(doc.Parsed, path)
		if coll == nil {
			return nil
		}
		for _, kv := range iterateCollection(coll) {
			if evalCondition(condition, kv.val, kv.key, compiledRe) {
				// A prohibited item was found
				return []document.ScanFinding{ctx.finding(doc, 1, "")}
			}
		}
		return nil
	}, nil
}

// ---------------------------------------------------------------------------
// Size primitives
// ---------------------------------------------------------------------------

func compileMinLength(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	path := strFieldFromMap(cfg, "field", "path")
	minVal := toInt(cfg["value"])
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		fv := resolveFieldPath(doc.Parsed, path)
		if fv == nil {
			return nil
		}
		s, ok := fv.(string)
		if !ok {
			return nil
		}
		if len(s) < minVal {
			return []document.ScanFinding{ctx.finding(doc, 1, "")}
		}
		return nil
	}, nil
}

func compileMaxLength(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	path := strFieldFromMap(cfg, "field", "path")
	maxVal := toInt(cfg["value"])
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		fv := resolveFieldPath(doc.Parsed, path)
		if fv == nil {
			return nil
		}
		s, ok := fv.(string)
		if !ok {
			return nil
		}
		if len(s) > maxVal {
			return []document.ScanFinding{ctx.finding(doc, 1, "")}
		}
		return nil
	}, nil
}

func compileMaxSizeBytes(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	maxBytes := toInt(cfg["value"])
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		if len([]byte(doc.Content)) > maxBytes {
			return []document.ScanFinding{ctx.finding(doc, 1, "")}
		}
		return nil
	}, nil
}

// ---------------------------------------------------------------------------
// Boolean combinators
// ---------------------------------------------------------------------------

func compileAllOf(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	childrenRaw, _ := cfg["matches"].([]any)
	var children []CheckFn
	for _, raw := range childrenRaw {
		m, err := toMap(raw)
		if err != nil {
			return nil, fmt.Errorf("all_of: child must be a map: %w", err)
		}
		fn, err := compileMatch(m, ctx)
		if err != nil {
			return nil, err
		}
		children = append(children, fn)
	}
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		var all []document.ScanFinding
		for _, fn := range children {
			results := fn(doc)
			if len(results) == 0 {
				return nil
			}
			all = append(all, results...)
		}
		return all
	}, nil
}

func compileAnyOf(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	childrenRaw, _ := cfg["matches"].([]any)
	var children []CheckFn
	for _, raw := range childrenRaw {
		m, err := toMap(raw)
		if err != nil {
			return nil, fmt.Errorf("any_of: child must be a map: %w", err)
		}
		fn, err := compileMatch(m, ctx)
		if err != nil {
			return nil, err
		}
		children = append(children, fn)
	}
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		for _, fn := range children {
			results := fn(doc)
			if len(results) > 0 {
				return results
			}
		}
		return nil
	}, nil
}

func compileNot(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	childRaw, ok := cfg["match"]
	if !ok {
		return nil, fmt.Errorf("not: missing 'match' key")
	}
	childMap, err := toMap(childRaw)
	if err != nil {
		return nil, fmt.Errorf("not: 'match' must be a map: %w", err)
	}
	child, err := compileMatch(childMap, ctx)
	if err != nil {
		return nil, err
	}
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		results := child(doc)
		if len(results) == 0 {
			return []document.ScanFinding{ctx.finding(doc, 1, "")}
		}
		return nil
	}, nil
}

func compilePerFileType(cfg map[string]any, ctx *ruleCtx) (CheckFn, error) {
	// cfg["file_types"] is a map from file_type string to match config
	// Support both "file_types" key and direct map (when the primitive receives its value directly)
	var branches map[string]any
	if ft, ok := cfg["file_types"]; ok {
		branches, _ = ft.(map[string]any)
	} else {
		// The cfg itself is the branches map (type key already stripped by caller if legacy-style)
		branches = cfg
		delete(branches, "type") // remove the "type" key if present
	}

	compiled := make(map[string]CheckFn, len(branches))
	for fileType, raw := range branches {
		m, err := toMap(raw)
		if err != nil {
			return nil, fmt.Errorf("per_file_type[%s]: branch must be a map: %w", fileType, err)
		}
		fn, err := compileMatch(m, ctx)
		if err != nil {
			return nil, err
		}
		compiled[fileType] = fn
	}
	return func(doc *document.ConfigDocument) []document.ScanFinding {
		fn, ok := compiled[doc.FileType]
		if !ok {
			return nil
		}
		return fn(doc)
	}, nil
}

// ---------------------------------------------------------------------------
// Collection condition evaluation
// ---------------------------------------------------------------------------

type kvPair struct {
	key any
	val any
}

func iterateCollection(coll any) []kvPair {
	var pairs []kvPair
	switch c := coll.(type) {
	case map[string]any:
		i := 0
		for k, v := range c {
			if i >= collectionIterationLimit {
				break
			}
			pairs = append(pairs, kvPair{key: k, val: v})
			i++
		}
	case []any:
		for i, v := range c {
			if i >= collectionIterationLimit {
				break
			}
			pairs = append(pairs, kvPair{key: i, val: v})
		}
	}
	return pairs
}

func precompileConditionRegex(condition map[string]any) *regexp.Regexp {
	if pat, ok := condition["matches"].(string); ok {
		re, err := compileRegex(pat)
		if err == nil {
			return re
		}
	}
	return nil
}

func evalCondition(condition map[string]any, item, key any, compiledRe *regexp.Regexp) bool {
	if eq, ok := condition["equals"]; ok {
		return fmt.Sprintf("%v", item) == fmt.Sprintf("%v", eq)
	}
	if neq, ok := condition["not_equals"]; ok {
		return fmt.Sprintf("%v", item) != fmt.Sprintf("%v", neq)
	}
	if _, ok := condition["matches"]; ok {
		s, isStr := item.(string)
		if !isStr {
			return false
		}
		if compiledRe != nil {
			return compiledRe.MatchString(s)
		}
		return false
	}
	if cfg, ok := toMapOK(condition["field_equals"]); ok {
		fieldName, _ := cfg["field"].(string)
		expected := cfg["value"]
		if fieldName == "_key" {
			return fmt.Sprintf("%v", key) == fmt.Sprintf("%v", expected)
		}
		if m, ok := item.(map[string]any); ok {
			return fmt.Sprintf("%v", m[fieldName]) == fmt.Sprintf("%v", expected)
		}
		return false
	}
	if cfg, ok := toMapOK(condition["field_starts_with"]); ok {
		fieldName, _ := cfg["field"].(string)
		prefix, _ := cfg["value"].(string)
		if fieldName == "_key" {
			ks, ok := key.(string)
			return ok && strings.HasPrefix(ks, prefix)
		}
		if m, ok := item.(map[string]any); ok {
			vs, ok := m[fieldName].(string)
			return ok && strings.HasPrefix(vs, prefix)
		}
		return false
	}
	if cfg, ok := toMapOK(condition["field_in"]); ok {
		fieldName, _ := cfg["field"].(string)
		valSet := toStringSet(cfg["values"])
		if fieldName == "_key" {
			_, in := valSet[fmt.Sprintf("%v", key)]
			return in
		}
		if m, ok := item.(map[string]any); ok {
			_, in := valSet[fmt.Sprintf("%v", m[fieldName])]
			return in
		}
		return false
	}
	if cfg, ok := toMapOK(condition["field_not_in"]); ok {
		fieldName, _ := cfg["field"].(string)
		valSet := toStringSet(cfg["values"])
		if fieldName == "_key" {
			_, in := valSet[fmt.Sprintf("%v", key)]
			return !in
		}
		if m, ok := item.(map[string]any); ok {
			_, in := valSet[fmt.Sprintf("%v", m[fieldName])]
			return !in
		}
		return false
	}
	if fieldName, ok := condition["has_field"].(string); ok {
		if m, ok := item.(map[string]any); ok {
			_, exists := m[fieldName]
			return exists
		}
		return false
	}
	return false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func resolveFieldPath(parsed map[string]any, path string) any {
	if parsed == nil || path == "" {
		return nil
	}
	var current any = parsed
	for _, seg := range strings.Split(path, ".") {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = m[seg]
		if current == nil {
			return nil
		}
	}
	return current
}

func isPresent(v any) bool {
	if v == nil {
		return false
	}
	switch vv := v.(type) {
	case string:
		return vv != ""
	case []any:
		return len(vv) > 0
	case map[string]any:
		return len(vv) > 0
	}
	return true
}

func extractCodeBlockLines(doc *document.ConfigDocument) map[int]struct{} {
	if doc.Parsed == nil {
		return nil
	}
	raw, ok := doc.Parsed["code_block_lines"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case map[int]bool:
		result := make(map[int]struct{}, len(v))
		for k := range v {
			result[k] = struct{}{}
		}
		return result
	case map[int]struct{}:
		return v
	case []any:
		result := make(map[int]struct{}, len(v))
		for _, item := range v {
			if n, ok := item.(int); ok {
				result[n] = struct{}{}
			}
		}
		return result
	}
	return nil
}

func parseSeverity(s string) (document.FindingSeverity, error) {
	switch strings.ToLower(s) {
	case "critical":
		return document.SeverityCritical, nil
	case "high":
		return document.SeverityHigh, nil
	case "warn", "warning":
		return document.SeverityWarn, nil
	case "info", "":
		return document.SeverityInfo, nil
	default:
		return document.SeverityInfo, fmt.Errorf("unknown severity %q", s)
	}
}

func strField(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// strFieldFromMap returns the first non-empty string value for the given keys.
func strFieldFromMap(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func toMap(v any) (map[string]any, error) {
	if m, ok := v.(map[string]any); ok {
		return m, nil
	}
	return nil, fmt.Errorf("not a map: %T", v)
}

func toMapOK(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func toStringSet(v any) map[string]struct{} {
	result := map[string]struct{}{}
	lst, ok := v.([]any)
	if !ok {
		return result
	}
	for _, item := range lst {
		result[fmt.Sprintf("%v", item)] = struct{}{}
	}
	return result
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}
