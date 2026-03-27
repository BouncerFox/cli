package platform

import "testing"

func TestVerdictExitCode_Pass(t *testing.T) {
	v := VerdictResponse{Verdict: "pass"}
	if v.ExitCode() != 0 {
		t.Errorf("pass should exit 0, got %d", v.ExitCode())
	}
}

func TestVerdictExitCode_Warn(t *testing.T) {
	v := VerdictResponse{Verdict: "warn"}
	if v.ExitCode() != 0 {
		t.Errorf("warn should exit 0, got %d", v.ExitCode())
	}
}

func TestVerdictExitCode_Fail(t *testing.T) {
	v := VerdictResponse{Verdict: "fail"}
	if v.ExitCode() != 1 {
		t.Errorf("fail should exit 1, got %d", v.ExitCode())
	}
}

func TestVerdictExitCode_Unknown(t *testing.T) {
	v := VerdictResponse{Verdict: "unknown"}
	if v.ExitCode() != 2 {
		t.Errorf("unknown verdict should exit 2, got %d", v.ExitCode())
	}
}
