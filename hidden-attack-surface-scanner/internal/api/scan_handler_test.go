package api

import "testing"

func TestNormalizeScanIDs(t *testing.T) {
	ids := normalizeScanIDs([]string{" scan-1 ", "", "scan-2", "scan-1", "scan-3", "scan-2"})
	want := []string{"scan-1", "scan-2", "scan-3"}
	if len(ids) != len(want) {
		t.Fatalf("normalizeScanIDs length = %d, want %d", len(ids), len(want))
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("normalizeScanIDs[%d] = %q, want %q", i, ids[i], want[i])
		}
	}
}

func TestIsFinishedScanStatus(t *testing.T) {
	cases := map[string]bool{
		"completed":        true,
		"failed":           true,
		"stopped":          true,
		"running":          false,
		"waiting_callback": false,
		"pending":          false,
		"":                 false,
	}

	for input, want := range cases {
		if got := isFinishedScanStatus(input); got != want {
			t.Fatalf("isFinishedScanStatus(%q) = %v, want %v", input, got, want)
		}
	}
}
