package parser

import "testing"

func TestRejectionDetails(t *testing.T) {
	t.Run("malformed YAML", func(t *testing.T) {
		doc := ParseFrontmatterMD("skill_md", "SKILL.md", "---\nname: [unclosed\n---\nBody")
		reason, line, rejected := RejectionDetails(doc)
		if !rejected {
			t.Fatal("expected rejected document")
		}
		if reason != RejectionReasonInvalidYAML {
			t.Errorf("reason = %q, want %q", reason, RejectionReasonInvalidYAML)
		}
		if line != 1 {
			t.Errorf("line = %d, want 1", line)
		}
	})

	t.Run("YAML reference", func(t *testing.T) {
		doc := ParseFrontmatterMD("skill_md", "SKILL.md", "---\nitems: [&item value, *item]\n---\nBody")
		reason, line, rejected := RejectionDetails(doc)
		if !rejected {
			t.Fatal("expected rejected document")
		}
		if reason != RejectionReasonYAMLReferences {
			t.Errorf("reason = %q, want %q", reason, RejectionReasonYAMLReferences)
		}
		if line != 2 {
			t.Errorf("line = %d, want 2", line)
		}
	})

	t.Run("valid document", func(t *testing.T) {
		doc := ParseFrontmatterMD("skill_md", "SKILL.md", "---\nname: valid\n---\nBody")
		if reason, line, rejected := RejectionDetails(doc); rejected {
			t.Errorf("unexpected rejection: reason=%q line=%d", reason, line)
		}
	})
}
