package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"hidden-attack-surface-scanner/pkg/payload"
)

func TestSendStandardRequestOnlyAppliesParamPayloads(t *testing.T) {
	var seenQuery string
	var seenHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenQuery = r.URL.RawQuery
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
		{
			Payload: payload.Payload{
				Type: payload.TypeParam,
				Key:  "url",
			},
			ResolvedValue: "https://oob.example/",
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
	if seenQuery != "url=https%3A%2F%2Foob.example%2F" {
		t.Fatalf("received query = %q", seenQuery)
	}
	if seenHost == "oob.example" {
		t.Fatalf("received host = %q, want original target host", seenHost)
	}
}

func TestCaptureRequestSnapshotIncludesReplayCommand(t *testing.T) {
	req, err := BuildStandardRequest(context.Background(), "https://target.example/api?ok=1", []payload.ResolvedPayload{
		{
			Payload:       payload.Payload{Type: payload.TypeParam, Key: "url"},
			ResolvedValue: "https://abc.oast.site/",
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
	if snapshot.URL != "https://target.example/api?ok=1&url=https%3A%2F%2Fabc.oast.site%2F" {
		t.Fatalf("snapshot.URL = %q", snapshot.URL)
	}
	if snapshot.RawRequest == "" || snapshot.ReplayCommand == "" {
		t.Fatalf("snapshot missing raw request or replay command: %#v", snapshot)
	}
	if !strings.Contains(snapshot.RawRequest, "User-Agent: scanner-test/1.0") {
		t.Fatalf("snapshot.RawRequest = %q, want custom header", snapshot.RawRequest)
	}
	if !strings.Contains(snapshot.ReplayCommand, "curl --http1.1") {
		t.Fatalf("snapshot.ReplayCommand = %q, want curl command", snapshot.ReplayCommand)
	}
}

func TestHTTPClientDoesNotFollowRedirects(t *testing.T) {
	redirectHits := 0
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer redirectTarget.Close()

	redirectSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL+"/next", http.StatusFound)
	}))
	defer redirectSource.Close()

	client, err := NewHTTPClient("", 3*time.Second)
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, redirectSource.URL, nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}

	statusCode, err := SendPreparedRequest(client, req)
	if err != nil {
		t.Fatalf("SendPreparedRequest() error = %v", err)
	}
	if statusCode != http.StatusFound {
		t.Fatalf("SendPreparedRequest() status = %d, want %d", statusCode, http.StatusFound)
	}
	if redirectHits != 0 {
		t.Fatalf("redirect target hits = %d, want 0", redirectHits)
	}
}

func TestNewHTTPClientRejectsUnknownProxyScheme(t *testing.T) {
	_, err := NewHTTPClient("gopher://127.0.0.1:70", time.Second)
	if err == nil {
		t.Fatal("NewHTTPClient() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "unsupported proxy scheme") {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
}

func TestNewHTTPClientAcceptsHTTPProxyScheme(t *testing.T) {
	client, err := NewHTTPClient("http://127.0.0.1:8080", time.Second)
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	if client.Transport == nil {
		t.Fatal("NewHTTPClient() transport = nil")
	}
	if client.CheckRedirect == nil {
		t.Fatal("NewHTTPClient() CheckRedirect = nil")
	}
	if _, parseErr := url.Parse("http://127.0.0.1:8080"); parseErr != nil {
		t.Fatalf("url.Parse() error = %v", parseErr)
	}
}
