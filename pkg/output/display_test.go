package output

import (
	"strings"
	"testing"
)

func TestSanitizeForDisplay_StripANSI(t *testing.T) {
	input := "hello \033[31mred\033[0m world"
	got := sanitizeForDisplay(input)
	if got != "hello red world" {
		t.Errorf("got %q, want %q", got, "hello red world")
	}
}

func TestSanitizeForDisplay_StripControlChars(t *testing.T) {
	input := "hello\x00world\x01test"
	got := sanitizeForDisplay(input)
	if got != "hello world test" {
		t.Errorf("got %q, want %q", got, "hello world test")
	}
}

func TestSanitizeForDisplay_PreserveTab(t *testing.T) {
	input := "hello\tworld"
	got := sanitizeForDisplay(input)
	if got != "hello\tworld" {
		t.Errorf("got %q, want %q", got, "hello\tworld")
	}
}

func TestSanitizeForDisplay_Truncate(t *testing.T) {
	input := make([]byte, 20000)
	for i := range input {
		input[i] = 'A'
	}
	got := sanitizeForDisplay(string(input))
	if len(got) != maxDisplayLineLength {
		t.Errorf("len = %d, want %d", len(got), maxDisplayLineLength)
	}
}

func TestSanitizeForDisplay_InvalidUTF8(t *testing.T) {
	input := "hello\xff\xfeworld"
	got := sanitizeForDisplay(input)
	if got == "" {
		t.Error("should produce non-empty output")
	}
	// Should contain replacement characters
	if !strings.ContainsRune(got, '\uFFFD') {
		t.Error("should contain Unicode replacement character for invalid bytes")
	}
}

func TestRenderMode_NoColor(t *testing.T) {
	rm := resolveRenderMode(true, false)
	if rm.colors {
		t.Error("colors should be off with noColor=true")
	}
	if rm.unicode {
		t.Error("unicode should be off with noColor=true")
	}
}

func TestRenderMode_TTY(t *testing.T) {
	rm := resolveRenderMode(false, true)
	if !rm.colors {
		t.Error("colors should be on for TTY")
	}
	if !rm.unicode {
		t.Error("unicode should be on for TTY")
	}
}

func TestRenderMode_Piped(t *testing.T) {
	rm := resolveRenderMode(false, false)
	if rm.colors {
		t.Error("colors should be off when piped")
	}
	if rm.unicode {
		t.Error("unicode should be off when piped")
	}
}

func TestSeverityBadge_Unicode(t *testing.T) {
	rm := renderMode{colors: true, unicode: true}
	badge := rm.severityBadge("critical")
	if badge == "" {
		t.Error("badge should not be empty")
	}
}

func TestSeverityBadge_ASCII(t *testing.T) {
	rm := renderMode{colors: false, unicode: false}
	badge := rm.severityBadge("critical")
	if badge != "[critical]" {
		t.Errorf("got %q, want %q", badge, "[critical]")
	}
}

