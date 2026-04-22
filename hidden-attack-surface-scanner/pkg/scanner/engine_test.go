package scanner

import (
	"testing"

	"hidden-attack-surface-scanner/pkg/payload"
)

func TestSplitHostPayloads(t *testing.T) {
	standard, host := splitHostPayloads([]payload.Payload{
		{Type: payload.TypeHeader, Key: "Referer"},
		{Type: payload.TypeHeader, Key: "Host"},
		{Type: payload.TypeParam, Key: "url"},
	})

	if len(standard) != 2 {
		t.Fatalf("standard payload count = %d, want 2", len(standard))
	}
	if len(host) != 1 {
		t.Fatalf("host payload count = %d, want 1", len(host))
	}
	if host[0].Key != "Host" {
		t.Fatalf("host payload key = %q, want Host", host[0].Key)
	}
}

func TestEstimateTotalRequestsCountsHostSeparately(t *testing.T) {
	total := estimateTotalRequests(StartScanRequest{
		Targets: []string{"https://example.com"},
	}, []payload.Payload{
		{Type: payload.TypeHeader, Key: "Referer"},
		{Type: payload.TypeHeader, Key: "Host"},
	})

	if total != 2 {
		t.Fatalf("estimateTotalRequests() = %d, want 2", total)
	}
}
