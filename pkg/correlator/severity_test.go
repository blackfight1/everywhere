package correlator

import "testing"

func TestEvaluateSeverity(t *testing.T) {
	if got := EvaluateSeverity("ldap", false, "mark"); got != "critical" {
		t.Fatalf("expected critical, got %s", got)
	}
	if got := EvaluateSeverity("dns", true, "drop"); got != "" {
		t.Fatalf("expected dropped own-ip event, got %s", got)
	}
}
