package parser

import "testing"

func TestComputeCodeBlockLines(t *testing.T) {
	tests := []struct {
		name string
		text string
		want map[int]bool
	}{
		{
			"no code blocks",
			"hello\nworld",
			map[int]bool{},
		},
		{
			"single backtick fence",
			"before\n```\ncode line\n```\nafter",
			map[int]bool{3: true},
		},
		{
			"tilde fence",
			"before\n~~~\ncode line\n~~~\nafter",
			map[int]bool{3: true},
		},
		{
			"fence with language tag",
			"```python\nprint('hi')\n```",
			map[int]bool{2: true},
		},
		{
			"multiple code blocks",
			"text\n```\nfirst\n```\ntext\n```\nsecond\n```",
			map[int]bool{3: true, 7: true},
		},
		{
			"unclosed fence includes rest",
			"text\n```\ncode1\ncode2",
			map[int]bool{3: true, 4: true},
		},
		{
			"empty string",
			"",
			map[int]bool{},
		},
		{
			"closing fence must match char",
			"```\ncode\n~~~\nstill code\n```",
			map[int]bool{2: true, 3: true, 4: true},
		},
		{
			"closing fence must be >= opening length",
			"````\ncode\n```\nstill code\n````",
			map[int]bool{2: true, 3: true, 4: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeCodeBlockLines(tt.text)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d lines, want %d: got=%v", len(got), len(tt.want), got)
			}
			for line := range tt.want {
				if !got[line] {
					t.Errorf("expected line %d in code block lines, got %v", line, got)
				}
			}
		})
	}
}
