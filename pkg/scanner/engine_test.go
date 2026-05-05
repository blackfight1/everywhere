package scanner

import (
	"testing"

	appconfig "github.com/blackfight1/everywhere/internal/config"
	"github.com/blackfight1/everywhere/pkg/payload"
)

func TestEstimateTotalRequestsOnlyCountsRawPayloads(t *testing.T) {
	total := estimateTotalRequests(StartScanRequest{
		Targets: []string{"https://example.com"},
	}, []payload.Payload{
		{Type: payload.TypeRaw, Key: "duplicate-host"},
		{Type: payload.TypeRaw, Key: "host-with-at"},
	}, 1)

	if total != 2 {
		t.Fatalf("estimateTotalRequests() = %d, want 2", total)
	}
}

func TestEstimateTotalRequestsExpandsProxyUnsafeVariants(t *testing.T) {
	total := estimateTotalRequests(StartScanRequest{
		Targets: []string{"https://example.com"},
	}, []payload.Payload{
		{Type: payload.TypeRaw, Key: "duplicate-host"},
		{Type: payload.TypeRaw, Key: proxyLocalSSHPayloadKey},
	}, 1)

	want := 1 + len(proxyUnsafeVariants())
	if total != want {
		t.Fatalf("estimateTotalRequests() = %d, want %d", total, want)
	}
}

func TestSelectPayloadsForModeOnlyIncludesActiveRaw(t *testing.T) {
	items := []payload.Payload{
		{Active: true, Group: "cracking_the_lens", Type: payload.TypeRaw, Key: "duplicate-host"},
		{Active: false, Group: "cracking_the_lens", Type: payload.TypeRaw, Key: "host-at-reversed"},
	}

	selected := selectPayloadsForMode(items, scanModeRaw)

	if len(selected) != 1 {
		t.Fatalf("selected payload count = %d, want 1", len(selected))
	}
	if selected[0].Key != "duplicate-host" {
		t.Fatalf("selected payloads = %#v", selected)
	}
}

func TestApplyDefaultsNormalizesModeToDefault(t *testing.T) {
	req := StartScanRequest{Mode: " full "}
	req.applyDefaults(applyDefaultsTestConfig())

	if req.Mode != scanModeRaw {
		t.Fatalf("mode = %q, want %q", req.Mode, scanModeRaw)
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
