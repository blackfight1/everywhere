package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hidden-attack-surface-scanner/pkg/payload"
)

func TestSendStandardRequestUsesReqHostForHostPayload(t *testing.T) {
	var seenHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	req, err := BuildStandardRequest(context.Background(), server.URL, []payload.ResolvedPayload{
		{
			Payload: payload.Payload{
				Type: payload.TypeHeader,
				Key:  "Host",
			},
			ResolvedValue: "oob.example",
		},
	}, nil)
	if err != nil {
		t.Fatalf("BuildStandardRequest() error = %v", err)
	}

	statusCode, err := SendPreparedRequest(server.Client(), req)
	if err != nil {
		t.Fatalf("SendPreparedRequest() error = %v", err)
	}
	if statusCode != http.StatusNoContent {
		t.Fatalf("SendPreparedRequest() status = %d, want %d", statusCode, http.StatusNoContent)
	}
	if seenHost != "oob.example" {
		t.Fatalf("received host = %q, want %q", seenHost, "oob.example")
	}
}

func TestCaptureRequestSnapshotIncludesReplayCommand(t *testing.T) {
	req, err := BuildStandardRequest(context.Background(), "https://target.example/api?ok=1", []payload.ResolvedPayload{
		{
			Payload: payload.Payload{Type: payload.TypeHeader, Key: "Host"},
			ResolvedValue: "spoofed.example",
		},
		{
			Payload: payload.Payload{Type: payload.TypeHeader, Key: "X-Forwarded-Host"},
			ResolvedValue: "abc.oast.site",
		},
	}, map[string]string{"User-Agent": "scanner-test/1.0"})
	if err != nil {
		t.Fatalf("BuildStandardRequest() error = %v", err)
	}

	snapshot, err := CaptureRequestSnapshot(req)
	if err != nil {
		t.Fatalf("CaptureRequestSnapshot() error = %v", err)
	}

	if snapshot.Method != http.MethodGet {
		t.Fatalf("snapshot.Method = %q, want %q", snapshot.Method, http.MethodGet)
	}
	if snapshot.URL != "https://target.example/api?ok=1" {
		t.Fatalf("snapshot.URL = %q", snapshot.URL)
	}
	if snapshot.RawRequest == "" || snapshot.ReplayCommand == "" {
		t.Fatalf("snapshot missing raw request or replay command: %#v", snapshot)
	}
	if !strings.Contains(snapshot.RawRequest, "Host: spoofed.example") {
		t.Fatalf("snapshot.RawRequest = %q, want Host override", snapshot.RawRequest)
	}
	if !strings.Contains(snapshot.ReplayCommand, "curl --http1.1") {
		t.Fatalf("snapshot.ReplayCommand = %q, want curl command", snapshot.ReplayCommand)
	}
}
