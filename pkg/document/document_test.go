package document

import "testing"

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		sev  FindingSeverity
		want int
	}{
		{SeverityInfo, 0},
		{SeverityWarn, 1},
		{SeverityHigh, 2},
		{SeverityCritical, 3},
	}
	for _, tt := range tests {
		if got := tt.sev.Level(); got != tt.want {
			t.Errorf("FindingSeverity(%q).Level() = %d, want %d", tt.sev, got, tt.want)
		}
	}
}

func TestSeverityLevel_Unknown(t *testing.T) {
	sev := FindingSeverity("bogus")
	if got := sev.Level(); got != -1 {
		t.Errorf("unknown severity Level() = %d, want -1", got)
	}
}

func TestSeverityLevel_Empty(t *testing.T) {
	sev := FindingSeverity("")
	if got := sev.Level(); got != -1 {
		t.Errorf("empty severity Level() = %d, want -1", got)
	}
}

func TestSeverityString(t *testing.T) {
	if got := SeverityCritical.String(); got != "critical" {
		t.Errorf("SeverityCritical.String() = %q, want %q", got, "critical")
	}
}
