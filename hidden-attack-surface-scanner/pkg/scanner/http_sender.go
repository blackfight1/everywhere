package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"hidden-attack-surface-scanner/pkg/payload"

	xproxy "golang.org/x/net/proxy"
)

func NewHTTPClient(proxyURL string, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
	}

	if proxyURL != "" {
		parsed, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("parse proxy url: %w", err)
		}
		switch parsed.Scheme {
		case "http", "https":
			transport.Proxy = http.ProxyURL(parsed)
		case "socks5", "socks5h":
			dialer, err := xproxy.FromURL(parsed, xproxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("create socks5 proxy: %w", err)
			}
			transport.Proxy = nil
			transport.DialContext = func(ctx context.Context, network string, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		default:
			return nil, fmt.Errorf("unsupported proxy scheme: %s", parsed.Scheme)
		}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

func SendStandardRequest(
	ctx context.Context,
	httpClient *http.Client,
	target string,
	payloads []payload.ResolvedPayload,
	customHeaders map[string]string,
) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("Cache-Control", "no-transform")
	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}
	for _, item := range payloads {
		switch item.Type {
		case payload.TypeHeader:
			if strings.EqualFold(item.Key, "Host") {
				req.Host = item.ResolvedValue
				continue
			}
			req.Header.Set(item.Key, item.ResolvedValue)
		case payload.TypeParam:
			query := req.URL.Query()
			query.Set(item.Key, item.ResolvedValue)
			req.URL.RawQuery = query.Encode()
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	return resp.StatusCode, nil
}
