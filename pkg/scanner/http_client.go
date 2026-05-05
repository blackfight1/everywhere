package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
