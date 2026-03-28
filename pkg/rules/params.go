package rules

// DefaultRuleParams returns a fresh copy of the default rule parameters.
func DefaultRuleParams() map[string]map[string]any {
	return map[string]map[string]any{
		"QA_003": {"min_description_length": 20},
		"PS_004": {"min_comment_length": 25},
		"QA_008": {"max_file_size_kb": 50.0},
		"SEC_002": {
			"url_allowlist": []string{
				"github.com",
				"githubusercontent.com",
				"localhost",
				"127.0.0.1",
				"npmjs.com",
				"pypi.org",
			},
		},
		"SEC_006": {"min_base64_length": 40},
		"SEC_018": {
			"hex_threshold_credential":    3.0,
			"hex_threshold_freetext":      3.5,
			"base64_threshold_credential": 4.0,
			"base64_threshold_freetext":   4.5,
			"mixed_threshold_credential":  4.5,
			"mixed_threshold_freetext":    5.0,
			"min_length_credential":       16,
			"min_length_freetext":         32,
		},
	}
}

var RuleParams = map[string]map[string]any{
	"QA_003": {"min_description_length": 20},
	"PS_004": {"min_comment_length": 25},
	"QA_008": {"max_file_size_kb": 50.0},
	"SEC_002": {
		"url_allowlist": []string{
			"github.com",
			"githubusercontent.com",
			"localhost",
			"127.0.0.1",
			"npmjs.com",
			"pypi.org",
		},
	},
	"SEC_006": {"min_base64_length": 40},
	"SEC_018": {
		"hex_threshold_credential":    3.0,
		"hex_threshold_freetext":      3.5,
		"base64_threshold_credential": 4.0,
		"base64_threshold_freetext":   4.5,
		"mixed_threshold_credential":  4.5,
		"mixed_threshold_freetext":    5.0,
		"min_length_credential":       16,
		"min_length_freetext":         32,
	},
}
