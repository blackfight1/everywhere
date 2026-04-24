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

func TestApplyDefaultsSetsBatchSize(t *testing.T) {
	req := StartScanRequest{}
	req.applyDefaults(applyDefaultsTestConfig())

	if req.BatchSize != 1500 {
		t.Fatalf("batch_size = %d, want 1500", req.BatchSize)
	}
}

func TestBatchCount(t *testing.T) {
	if got := batchCount(0, 1500); got != 0 {
		t.Fatalf("batchCount(0, 1500) = %d, want 0", got)
	}
	if got := batchCount(1500, 1500); got != 1 {
		t.Fatalf("batchCount(1500, 1500) = %d, want 1", got)
	}
	if got := batchCount(1501, 1500); got != 2 {
		t.Fatalf("batchCount(1501, 1500) = %d, want 2", got)
	}
}

func TestChunkTargets(t *testing.T) {
	targets := []string{"a", "b", "c", "d", "e"}
	chunks := chunkTargets(targets, 2)

	if len(chunks) != 3 {
		t.Fatalf("chunk count = %d, want 3", len(chunks))
	}
	if len(chunks[0]) != 2 || chunks[0][0] != "a" || chunks[0][1] != "b" {
		t.Fatalf("chunk[0] = %#v", chunks[0])
	}
	if len(chunks[1]) != 2 || chunks[1][0] != "c" || chunks[1][1] != "d" {
		t.Fatalf("chunk[1] = %#v", chunks[1])
	}
	if len(chunks[2]) != 1 || chunks[2][0] != "e" {
		t.Fatalf("chunk[2] = %#v", chunks[2])
	}
}

func applyDefaultsTestConfig() appconfig.Config {
	return appconfig.Config{
		Scanner: appconfig.ScannerConfig{
			DefaultConcurrency:   10,
			DefaultBatchSize:     1500,
			DefaultRateLimit:     20,
			DefaultTimeoutMinute: 1440,
		},
	}
}
