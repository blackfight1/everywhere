package scanner

import (
	"strings"
	"testing"

	"github.com/blackfight1/everywhere/pkg/payload"
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

func TestBuildCrackingRequestAbsoluteURLHostMismatch(t *testing.T) {
	req, err := BuildCrackingRequest("http://example.com/api?q=1", payload.Payload{
		Type: payload.TypeRaw,
		Key:  "absolute-url-host-mismatch",
	}, "abc.oast.pro")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "GET https://abc.oast.pro/api?q=1 HTTP/1.1\r\nHost: example.com\r\n"
	if !strings.Contains(string(req.RawBytes), want) {
		t.Fatalf("unexpected raw request: %s", string(req.RawBytes))
	}
	if req.UseTLS {
		t.Fatalf("expected non-TLS transport for http target")
	}
}

func TestBuildCrackingRequestRejectsUnsupportedPayload(t *testing.T) {
	_, err := BuildCrackingRequest("https://example.com", payload.Payload{
		Type: payload.TypeRaw,
		Key:  "sni-host-mismatch",
	}, "abc.oast.pro")
	if err == nil {
		t.Fatal("expected unsupported payload error")
	}
}

func TestBuildProxyUnsafeRequestGET(t *testing.T) {
	req, err := BuildProxyUnsafeRequest("https://target.example/path", ProxyUnsafeVariant{
		Method:   "GET",
		Upstream: "127.0.0.1:22",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(req.RawBytes), "GET http://127.0.0.1:22 HTTP/1.1\r\nHost: target.example\r\n") {
		t.Fatalf("unexpected raw request: %s", string(req.RawBytes))
	}
	if !req.UseTLS {
		t.Fatalf("expected TLS request")
	}
}

func TestBuildProxyUnsafeRequestCONNECT(t *testing.T) {
	req, err := BuildProxyUnsafeRequest("http://target.example", ProxyUnsafeVariant{
		Method:   "CONNECT",
		Upstream: "localhost:22",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(req.RawBytes), "CONNECT localhost:22 HTTP/1.1\r\nHost: target.example\r\n") {
		t.Fatalf("unexpected raw request: %s", string(req.RawBytes))
	}
	if req.UseTLS {
		t.Fatalf("expected plain TCP request")
	}
}
