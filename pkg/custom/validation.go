package custom

import (
	"fmt"
	"regexp"
	"strings"
)

// knownPrimitives is the set of match type names recognised by compilePrimitive.
var knownPrimitives = map[string]struct{}{
	"line_pattern":         {},
	"line_patterns":        {},
	"content_contains":     {},
	"content_not_contains": {},
	"field_equals":         {},
	"field_exists":         {},
	"field_missing":        {},
	"field_in":             {},
	"field_not_in":         {},
	"field_matches":        {},
	"collection_any":       {},
	"collection_none":      {},
	"min_length":           {},
	"max_length":           {},
	"max_size_bytes":       {},
	"all_of":               {},
	"any_of":               {},
	"not":                  {},
	"per_file_type":        {},
}

// allowedTopLevelKeys lists the keys permitted at the rule's top level.
var allowedTopLevelKeys = map[string]struct{}{
	"id":          {},
	"name":        {},
	"description": {},
	"severity":    {},
	"remediation": {},
	"category":    {},
	"file_types":  {},
	"match":       {},
}

// validSeverities lists acceptable severity values (lower-cased).
var validSeverities = map[string]struct{}{
	"critical": {},
	"high":     {},
	"warn":     {},
	"info":     {},
}

// idPattern validates rule ID format: 2-5 uppercase letters, underscore, 3 digits.
var idPattern = regexp.MustCompile(`^[A-Z]{2,5}_\d{3}$`)

// Validate checks a raw rule map for structural and type correctness before
// it is passed to Compile. It returns a descriptive error on the first problem found.
func Validate(rule map[string]any) error {
	ruleID := "<unknown>"
	if s, ok := rule["id"].(string); ok && s != "" {
		ruleID = s
	}

	// --- unknown top-level keys ---
	for k := range rule {
		if _, ok := allowedTopLevelKeys[k]; !ok {
			return fmt.Errorf("rule %q: unknown top-level key %q", ruleID, k)
		}
	}

	// --- required: id ---
	idRaw, ok := rule["id"]
	if !ok {
		return fmt.Errorf("rule %q: missing required field \"id\"", ruleID)
	}
	idStr, ok := idRaw.(string)
	if !ok || idStr == "" {
		return fmt.Errorf("rule %q: \"id\" must be a non-empty string", ruleID)
	}
	if !idPattern.MatchString(idStr) {
		return fmt.Errorf("rule %q: \"id\" must match format XX_NNN (e.g. SEC_001, CUST_012)", ruleID)
	}

	// --- required: severity ---
	sevRaw, ok := rule["severity"]
	if !ok {
		return fmt.Errorf("rule %q: missing required field \"severity\"", ruleID)
	}
	sevStr, ok := sevRaw.(string)
	if !ok {
		return fmt.Errorf("rule %q: \"severity\" must be a string", ruleID)
	}
	if _, valid := validSeverities[strings.ToLower(sevStr)]; !valid {
		return fmt.Errorf("rule %q: invalid severity %q (must be one of: critical, high, warn, info)", ruleID, sevStr)
	}

	// --- required: match ---
	matchRaw, ok := rule["match"]
	if !ok {
		return fmt.Errorf("rule %q: missing required field \"match\"", ruleID)
	}
	matchMap, ok := matchRaw.(map[string]any)
	if !ok {
		return fmt.Errorf("rule %q: \"match\" must be a map", ruleID)
	}
	if err := validateMatch(matchMap); err != nil {
		return fmt.Errorf("rule %q: %w", ruleID, err)
	}

	// --- optional field types ---
	for _, key := range []string{"name", "description", "remediation", "category"} {
		if v, exists := rule[key]; exists {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("rule %q: %q must be a string", ruleID, key)
			}
		}
	}

	if v, exists := rule["file_types"]; exists {
		lst, ok := v.([]any)
		if !ok {
			return fmt.Errorf("rule %q: \"file_types\" must be a list", ruleID)
		}
		for i, item := range lst {
			if _, ok := item.(string); !ok {
				return fmt.Errorf("rule %q: \"file_types[%d]\" must be a string", ruleID, i)
			}
		}
	}

	return nil
}

// validateMatch recursively validates a match configuration map.
func validateMatch(cfg map[string]any) error {
	// New-style: has "type" key
	if typeRaw, hasType := cfg["type"]; hasType {
		typeName, ok := typeRaw.(string)
		if !ok {
			return fmt.Errorf("match \"type\" must be a string")
		}
		if _, known := knownPrimitives[typeName]; !known {
			return fmt.Errorf("unknown match type %q", typeName)
		}
		return validatePrimitive(typeName, cfg)
	}

	// Legacy multi-key style: each key is a primitive name
	for key := range cfg {
		if _, known := knownPrimitives[key]; !known {
			return fmt.Errorf("unknown match type %q", key)
		}
		// For legacy style, the value may be a sub-map or a scalar.
		// If it's a sub-map, validate it as that primitive type.
		if sub, ok := cfg[key].(map[string]any); ok {
			if err := validatePrimitive(key, sub); err != nil {
				return err
			}
		}
	}

	return nil
}

// validatePrimitive checks primitive-specific constraints (e.g. regex validity).
func validatePrimitive(typeName string, cfg map[string]any) error {
	switch typeName {
	case "line_pattern":
		return validateRegexField(cfg, "pattern", "line_pattern")
	case "line_patterns":
		return validatePatternsList(cfg)
	case "field_matches":
		return validateRegexField(cfg, "pattern", "field_matches")
	case "all_of":
		return validateCombinatorChildren(cfg, "all_of")
	case "any_of":
		return validateCombinatorChildren(cfg, "any_of")
	case "not":
		return validateNotChild(cfg)
	case "per_file_type":
		return validatePerFileType(cfg)
	}
	return nil
}

// validateRegexField checks that cfg[key] is a compilable regex.
func validateRegexField(cfg map[string]any, key, context string) error {
	patRaw, ok := cfg[key]
	if !ok {
		return nil // pattern may be optional at validation time
	}
	patStr, ok := patRaw.(string)
	if !ok {
		return fmt.Errorf("%s: %q must be a string", context, key)
	}
	if _, err := regexp.Compile(patStr); err != nil {
		return fmt.Errorf("%s: invalid regex in %q: %w", context, key, err)
	}
	return nil
}

// validatePatternsList validates each entry in a line_patterns "patterns" list.
func validatePatternsList(cfg map[string]any) error {
	patsRaw, ok := cfg["patterns"]
	if !ok {
		return nil
	}
	lst, ok := patsRaw.([]any)
	if !ok {
		return fmt.Errorf("line_patterns: \"patterns\" must be a list")
	}
	for i, item := range lst {
		switch v := item.(type) {
		case string:
			if _, err := regexp.Compile(v); err != nil {
				return fmt.Errorf("line_patterns: invalid regex at index %d: %w", i, err)
			}
		case map[string]any:
			if patStr, ok := v["pattern"].(string); ok {
				if _, err := regexp.Compile(patStr); err != nil {
					return fmt.Errorf("line_patterns: invalid regex at index %d: %w", i, err)
				}
			}
		}
	}
	return nil
}

// validateCombinatorChildren validates each child in an all_of/any_of "matches" list.
func validateCombinatorChildren(cfg map[string]any, context string) error {
	childrenRaw, ok := cfg["matches"]
	if !ok {
		return nil
	}
	lst, ok := childrenRaw.([]any)
	if !ok {
		return fmt.Errorf("%s: \"matches\" must be a list", context)
	}
	for i, raw := range lst {
		m, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: child at index %d must be a map", context, i)
		}
		if err := validateMatch(m); err != nil {
			return fmt.Errorf("%s: child %d: %w", context, i, err)
		}
	}
	return nil
}

// validateNotChild validates the "match" child inside a not primitive.
func validateNotChild(cfg map[string]any) error {
	childRaw, ok := cfg["match"]
	if !ok {
		return nil
	}
	m, ok := childRaw.(map[string]any)
	if !ok {
		return fmt.Errorf("not: \"match\" must be a map")
	}
	return validateMatch(m)
}

// validatePerFileType validates each branch in a per_file_type primitive.
func validatePerFileType(cfg map[string]any) error {
	// Branches may be under "file_types" key or directly in cfg (minus "type").
	branches, ok := cfg["file_types"].(map[string]any)
	if !ok {
		// Direct style: iterate cfg keys except "type"
		for k, v := range cfg {
			if k == "type" {
				continue
			}
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if err := validateMatch(m); err != nil {
				return fmt.Errorf("per_file_type[%s]: %w", k, err)
			}
		}
		return nil
	}
	for fileType, raw := range branches {
		m, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("per_file_type[%s]: branch must be a map", fileType)
		}
		if err := validateMatch(m); err != nil {
			return fmt.Errorf("per_file_type[%s]: %w", fileType, err)
		}
	}
	return nil
}
