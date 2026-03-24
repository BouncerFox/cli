package parser

import (
	"strings"
	"testing"
)

func TestParseJSONConfig_Basic(t *testing.T) {
	content := readFixture(t, "../../testdata/settings/basic.json")
	doc := ParseJSONConfig("settings_json", ".claude/settings.json", content)

	if doc.FileType != "settings_json" {
		t.Errorf("FileType = %q, want settings_json", doc.FileType)
	}
	if _, ok := doc.Parsed["_parse_error"]; ok {
		t.Error("unexpected _parse_error")
	}
	tools, ok := doc.Parsed["allowedTools"]
	if !ok {
		t.Error("allowedTools not found in parsed")
	}
	toolList, ok := tools.([]any)
	if !ok {
		t.Fatalf("allowedTools wrong type: %T", tools)
	}
	if len(toolList) != 2 {
		t.Errorf("allowedTools length = %d, want 2", len(toolList))
	}
}

func TestParseJSONConfig_MCP(t *testing.T) {
	content := readFixture(t, "../../testdata/mcp/basic.json")
	doc := ParseJSONConfig("mcp_json", ".mcp.json", content)

	if doc.FileType != "mcp_json" {
		t.Errorf("FileType = %q, want mcp_json", doc.FileType)
	}
	servers, ok := doc.Parsed["mcpServers"]
	if !ok {
		t.Error("mcpServers not found in parsed")
	}
	serversMap, ok := servers.(map[string]any)
	if !ok {
		t.Fatalf("mcpServers wrong type: %T", servers)
	}
	if _, ok := serversMap["my-server"]; !ok {
		t.Error("my-server not found in mcpServers")
	}
}

func TestParseJSONConfig_DeepNesting(t *testing.T) {
	content := readFixture(t, "../../testdata/settings/deep-nested.json")
	doc := ParseJSONConfig("settings_json", "settings.json", content)

	parseErr, _ := doc.Parsed["_parse_error"].(bool)
	if !parseErr {
		t.Error("expected _parse_error for deep nesting")
	}
	reason, _ := doc.Parsed["_reason"].(string)
	if reason != "json_nesting_depth" {
		t.Errorf("_reason = %q, want json_nesting_depth", reason)
	}
}

func TestParseJSONConfig_InvalidJSON(t *testing.T) {
	doc := ParseJSONConfig("settings_json", "settings.json", "{invalid json")

	parseErr, _ := doc.Parsed["_parse_error"].(bool)
	if !parseErr {
		t.Error("expected _parse_error for invalid JSON")
	}
}

func TestParseJSONConfig_BinaryContent(t *testing.T) {
	doc := ParseJSONConfig("settings_json", "settings.json", "{\x00\"key\": 1}")

	parseErr, _ := doc.Parsed["_parse_error"].(bool)
	if !parseErr {
		t.Error("expected _parse_error for binary content")
	}
}

func TestParseJSONConfig_TooLarge(t *testing.T) {
	content := "{\"key\": \"" + strings.Repeat("x", 600*1024) + "\"}"
	doc := ParseJSONConfig("settings_json", "settings.json", content)

	parseErr, _ := doc.Parsed["_parse_error"].(bool)
	if !parseErr {
		t.Error("expected _parse_error for oversized content")
	}
	reason, _ := doc.Parsed["_reason"].(string)
	if reason != "content_too_large" {
		t.Errorf("_reason = %q, want content_too_large", reason)
	}
}

func TestFindJSONKeyLine(t *testing.T) {
	content := "{\n  \"foo\": 1,\n  \"bar\": 2\n}"
	if got := FindJSONKeyLine(content, "bar"); got != 3 {
		t.Errorf("FindJSONKeyLine(bar) = %d, want 3", got)
	}
	if got := FindJSONKeyLine(content, "missing"); got != 1 {
		t.Errorf("FindJSONKeyLine(missing) = %d, want 1", got)
	}
}
