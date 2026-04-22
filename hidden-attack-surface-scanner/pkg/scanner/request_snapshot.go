package scanner

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
)

type RequestSnapshot struct {
	Method        string
	URL           string
	RawRequest    string
	ReplayCommand string
}

func CaptureRequestSnapshot(req *http.Request) (RequestSnapshot, error) {
	if req == nil {
		return RequestSnapshot{}, fmt.Errorf("request is nil")
	}

	var raw bytes.Buffer
	if err := req.Write(&raw); err != nil {
		return RequestSnapshot{}, fmt.Errorf("serialize request: %w", err)
	}

	return RequestSnapshot{
		Method:        req.Method,
		URL:           req.URL.String(),
		RawRequest:    raw.String(),
		ReplayCommand: buildCurlCommand(req),
	}, nil
}

func BuildRawRequestSnapshot(targetURL string, rawRequest RawRequest) RequestSnapshot {
	return RequestSnapshot{
		Method:        detectRawRequestMethod(rawRequest.RawBytes),
		URL:           targetURL,
		RawRequest:    string(rawRequest.RawBytes),
		ReplayCommand: buildRawReplayCommand(rawRequest),
	}
}

func buildCurlCommand(req *http.Request) string {
	parts := []string{"curl", "--http1.1"}
	if req.Method != "" && !strings.EqualFold(req.Method, http.MethodGet) {
		parts = append(parts, "-X", shellQuote(req.Method))
	}

	hostHeaderIncluded := false
	if req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		parts = append(parts, "-H", shellQuote("Host: "+req.Host))
		hostHeaderIncluded = true
	}

	keys := make([]string, 0, len(req.Header))
	for key := range req.Header {
		if hostHeaderIncluded && strings.EqualFold(key, "Host") {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		values := append([]string(nil), req.Header.Values(key)...)
		sort.Strings(values)
		for _, value := range values {
			parts = append(parts, "-H", shellQuote(fmt.Sprintf("%s: %s", key, value)))
		}
	}

	parts = append(parts, shellQuote(req.URL.String()))
	return strings.Join(parts, " ")
}

func buildRawReplayCommand(rawRequest RawRequest) string {
	payload := string(rawRequest.RawBytes)
	if payload != "" && !strings.HasSuffix(payload, "\n") {
		payload += "\n"
	}

	if rawRequest.UseTLS {
		serverName := rawRequest.SNIHost
		if strings.TrimSpace(serverName) == "" {
			serverName = splitHost(rawRequest.Address)
		}
		return fmt.Sprintf(
			"cat <<'EOF' | openssl s_client -quiet -connect %s -servername %s\n%sEOF",
			rawRequest.Address,
			serverName,
			payload,
		)
	}

	host, port, err := net.SplitHostPort(rawRequest.Address)
	if err != nil {
		return fmt.Sprintf("cat <<'EOF' | nc %s\n%sEOF", rawRequest.Address, payload)
	}
	return fmt.Sprintf("cat <<'EOF' | nc %s %s\n%sEOF", host, port, payload)
}

func detectRawRequestMethod(raw []byte) string {
	line := string(raw)
	if idx := strings.Index(line, "\r\n"); idx >= 0 {
		line = line[:idx]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "RAW"
	}
	return fields[0]
}

func splitHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
