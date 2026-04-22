package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
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

	statusCode, err := SendStandardRequest(context.Background(), server.Client(), server.URL, []payload.ResolvedPayload{
		{
			Payload: payload.Payload{
				Type: payload.TypeHeader,
				Key:  "Host",
			},
			ResolvedValue: "oob.example",
		},
	}, nil)
	if err != nil {
		t.Fatalf("SendStandardRequest() error = %v", err)
	}
	if statusCode != http.StatusNoContent {
		t.Fatalf("SendStandardRequest() status = %d, want %d", statusCode, http.StatusNoContent)
	}
	if seenHost != "oob.example" {
		t.Fatalf("received host = %q, want %q", seenHost, "oob.example")
	}
}
