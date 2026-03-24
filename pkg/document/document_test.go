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
