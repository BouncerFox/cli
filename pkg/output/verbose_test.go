package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bouncerfox/cli/pkg/document"
)

func TestWriteCodeFrame_ShowsContext(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.md")
	os.WriteFile(file, []byte("line1\nline2\nline3\nline4\nline5\nline6\nline7\n"), 0644)

	f := document.ScanFinding{
		RuleID:   "SEC_002",
		Severity: "high",
		Evidence: map[string]any{"file": file, "line": 4},
	}
	var buf bytes.Buffer
	rm := renderMode{colors: false, unicode: false}
	writeCodeFrame(&buf, rm, f)
	out := buf.String()
	if out == "" {
		t.Fatal("code frame should not be empty")
	}
	if !strings.Contains(out, "line3") {
		t.Error("should show line before finding")
	}
	if !strings.Contains(out, "line4") {
		t.Error("should show the finding line")
	}
	if !strings.Contains(out, "line5") {
		t.Error("should show line after finding")
	}
}

func TestWriteCodeFrame_MasksSecrets(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.md")
	os.WriteFile(file, []byte("line1\nline2\napi_key = sk-secret-value-here\nline4\nline5\n"), 0644)

	f := document.ScanFinding{
		RuleID:   "SEC_001",
		Severity: "critical",
		Evidence: map[string]any{"file": file, "line": 3},
	}
	var buf bytes.Buffer
	rm := renderMode{colors: false, unicode: false}
	writeCodeFrame(&buf, rm, f)
	out := buf.String()
	if strings.Contains(out, "sk-secret") {
		t.Error("should mask secret content")
	}
	if !strings.Contains(out, "***") {
		t.Error("should contain mask characters")
	}
}

func TestWriteCodeFrame_MissingFile(t *testing.T) {
	f := document.ScanFinding{
		RuleID:   "SEC_002",
		Severity: "high",
		Evidence: map[string]any{"file": "/nonexistent/file.md", "line": 1},
	}
	var buf bytes.Buffer
	rm := renderMode{colors: false, unicode: false}
	writeCodeFrame(&buf, rm, f)
	if buf.Len() > 0 {
		t.Error("missing file should produce no code frame")
	}
}

func TestWriteCodeFrame_LineOutOfRange(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.md")
	os.WriteFile(file, []byte("one line\n"), 0644)

	f := document.ScanFinding{
		RuleID:   "SEC_002",
		Severity: "high",
		Evidence: map[string]any{"file": file, "line": 999},
	}
	var buf bytes.Buffer
	rm := renderMode{colors: false, unicode: false}
	writeCodeFrame(&buf, rm, f)
	if buf.Len() > 0 {
		t.Error("out-of-range line should produce no code frame")
	}
}

func TestWriteCodeFrame_UnicodeBoxDrawing(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.md")
	os.WriteFile(file, []byte("line1\nline2\nline3\n"), 0644)

	f := document.ScanFinding{
		RuleID:   "SEC_002",
		Severity: "high",
		Evidence: map[string]any{"file": file, "line": 2},
	}
	var buf bytes.Buffer
	rm := renderMode{colors: false, unicode: true}
	writeCodeFrame(&buf, rm, f)
	out := buf.String()
	if !strings.Contains(out, "\u256d") {
		t.Error("should use unicode box-drawing in unicode mode")
	}
}

func TestWriteCodeFrame_ASCIIBoxDrawing(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.md")
	os.WriteFile(file, []byte("line1\nline2\nline3\n"), 0644)

	f := document.ScanFinding{
		RuleID:   "SEC_002",
		Severity: "high",
		Evidence: map[string]any{"file": file, "line": 2},
	}
	var buf bytes.Buffer
	rm := renderMode{colors: false, unicode: false}
	writeCodeFrame(&buf, rm, f)
	out := buf.String()
	if !strings.Contains(out, "+---") {
		t.Error("should use ASCII box in non-unicode mode")
	}
}

func TestWriteCodeFrame_SEC018Masked(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.md")
	os.WriteFile(file, []byte("line1\nhigh_entropy_string_abcdef123456\nline3\n"), 0644)

	f := document.ScanFinding{
		RuleID:   "SEC_018",
		Severity: "high",
		Evidence: map[string]any{"file": file, "line": 2},
	}
	var buf bytes.Buffer
	rm := renderMode{colors: false, unicode: false}
	writeCodeFrame(&buf, rm, f)
	out := buf.String()
	if strings.Contains(out, "high_entropy") {
		t.Error("SEC_018 lines should be masked")
	}
}
