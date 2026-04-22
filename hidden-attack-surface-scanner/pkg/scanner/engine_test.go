package scanner

import (
	"testing"

	appconfig "hidden-attack-surface-scanner/internal/config"
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

func TestSelectPayloadsForModeQuick(t *testing.T) {
	items := []payload.Payload{
		{Active: true, Group: "standard", Type: payload.TypeHeader, Key: "Referer"},
		{Active: true, Group: "standard", Type: payload.TypeHeader, Key: "Host"},
		{Active: true, Group: "standard", Type: payload.TypeParam, Key: "url"},
		{Active: true, Group: "cracking_the_lens", Type: payload.TypeRaw, Key: "duplicate-host"},
		{Active: true, Group: "cracking_the_lens", Type: payload.TypeRaw, Key: "host-with-hash"},
		{Active: false, Group: "cracking_the_lens", Type: payload.TypeRaw, Key: "sni-host-mismatch"},
	}

	selected := selectPayloadsForMode(items, scanModeQuick)

	if len(selected) != 3 {
		t.Fatalf("quick payload count = %d, want 3", len(selected))
	}
	if selected[0].Key != "Referer" || selected[1].Key != "Host" || selected[2].Key != "duplicate-host" {
		t.Fatalf("quick payloads = %#v", selected)
	}
}

func TestSelectPayloadsForModeFull(t *testing.T) {
	items := []payload.Payload{
		{Active: true, Group: "standard", Type: payload.TypeHeader, Key: "Referer"},
		{Active: true, Group: "standard", Type: payload.TypeParam, Key: "url"},
		{Active: true, Group: "cracking_the_lens", Type: payload.TypeRaw, Key: "duplicate-host"},
		{Active: false, Group: "cracking_the_lens", Type: payload.TypeRaw, Key: "host-with-hash"},
	}

	selected := selectPayloadsForMode(items, scanModeFull)

	if len(selected) != 3 {
		t.Fatalf("full payload count = %d, want 3", len(selected))
	}
}

func TestApplyDefaultsNormalizesMode(t *testing.T) {
	req := StartScanRequest{Mode: " FULL "}
	req.applyDefaults(applyDefaultsTestConfig())

	if req.Mode != scanModeFull {
		t.Fatalf("mode = %q, want %q", req.Mode, scanModeFull)
	}
}

func applyDefaultsTestConfig() appconfig.Config {
	return appconfig.Config{
		Scanner: appconfig.ScannerConfig{
			DefaultConcurrency:   10,
			DefaultRateLimit:     20,
			DefaultTimeoutMinute: 1440,
		},
	}
}
