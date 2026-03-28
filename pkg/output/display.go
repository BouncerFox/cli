package output

import (
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

const maxDisplayLineLength = 10_000

var ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// sanitizeForDisplay removes ANSI escapes, control characters, and invalid
// UTF-8 from a line of file content before terminal display. Tabs are preserved.
func sanitizeForDisplay(line string) string {
	line = ansiEscapeRe.ReplaceAllString(line, "")

	var b strings.Builder
	b.Grow(len(line))
	for i := 0; i < len(line); {
		r, size := utf8.DecodeRuneInString(line[i:])
		if r == utf8.RuneError && size <= 1 {
			b.WriteRune('\uFFFD')
			i++
			continue
		}
		if r < 0x20 && r != '\t' {
			b.WriteByte(' ')
		} else {
			b.WriteRune(r)
		}
		i += size
	}
	result := b.String()

	if len(result) > maxDisplayLineLength {
		result = result[:maxDisplayLineLength]
	}
	return result
}

// renderMode holds the resolved rendering configuration.
type renderMode struct {
	colors  bool
	unicode bool
}

// resolveRenderMode determines rendering based on flags and TTY status.
func resolveRenderMode(noColor bool, isTTY bool) renderMode {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return renderMode{}
	}
	return renderMode{colors: isTTY, unicode: isTTY}
}

// IsTerminalStdout returns true if stdout is an interactive terminal.
func IsTerminalStdout() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

const (
	ansiGreen     = "\033[32m"
	ansiGreenBold = "\033[1;32m"
	ansiDim       = "\033[2m"
)

func (rm renderMode) severityBadge(severity string) string {
	if !rm.unicode {
		return "[" + severity + "]"
	}
	switch severity {
	case "critical":
		return rm.color(ansiRedBold, "\u2717 critical")
	case "high":
		return rm.color(ansiRed, "\u26a0 high     ")
	case "warn":
		return rm.color(ansiYellow, "\u26a0 warn     ")
	case "info":
		return rm.color(ansiCyan, "\u2139 info     ")
	default:
		return severity
	}
}

func (rm renderMode) passBadge() string {
	if !rm.unicode {
		return "[PASS]"
	}
	return rm.color(ansiGreenBold, "\u2713 PASS")
}

func (rm renderMode) failBadge() string {
	if !rm.unicode {
		return "[FAIL]"
	}
	return rm.color(ansiRedBold, "\u2717 FAIL")
}

func (rm renderMode) bold(s string) string {
	if !rm.colors {
		return s
	}
	return ansiBold + s + ansiReset
}

func (rm renderMode) dim(s string) string {
	if !rm.colors {
		return s
	}
	return ansiDim + s + ansiReset
}

func (rm renderMode) color(code, s string) string {
	if !rm.colors {
		return s
	}
	return code + s + ansiReset
}

func (rm renderMode) arrow() string {
	if rm.unicode {
		return "\u2192"
	}
	return "->"
}

func (rm renderMode) dot() string {
	if rm.unicode {
		return "\u00b7"
	}
	return "."
}

func (rm renderMode) boxTop() string {
	if rm.unicode {
		return "  \u256d\u2500\u2500\u2500"
	}
	return "  +---"
}

func (rm renderMode) boxLine() string {
	if rm.unicode {
		return "  \u2502"
	}
	return "  |"
}

func (rm renderMode) boxBottom() string {
	if rm.unicode {
		return "  \u2570\u2500\u2500\u2500"
	}
	return "  +---"
}
