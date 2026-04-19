package scanner

import (
	"strings"
	"testing"

	"hidden-attack-surface-scanner/pkg/payload"
)

func TestBuildCrackingRequestDuplicateHost(t *testing.T) {
	req, err := BuildCrackingRequest("https://example.com/path", payload.Payload{
		Type: payload.TypeRaw,
		Key:  "duplicate-host",
	}, "abc.oast.pro")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(req.RawBytes), "Host: example.com\r\nHost: abc.oast.pro") {
		t.Fatalf("unexpected raw request: %s", string(req.RawBytes))
	}
	if !req.UseTLS {
		t.Fatalf("expected TLS request")
	}
}

func TestBuildAltTargets(t *testing.T) {
	targets := buildAltTargets("https://example.com/api", []int{8443, 8080})
	if len(targets) != 2 {
		t.Fatalf("expected 2 alt targets, got %d", len(targets))
	}
	if targets[0] != "https://example.com:8443/api" {
		t.Fatalf("unexpected first alt target: %s", targets[0])
	}
}
