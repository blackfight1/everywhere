package oob

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	interactclient "github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

type CorrelationEntry struct {
	ScanTaskID  string
	TargetURL   string
	PayloadType string
	PayloadKey  string
	PayloadVal  string
	SentAt      time.Time
	FullOOBURL  string
	OwnIPProbe  bool
}

type Client struct {
	client       *interactclient.Client
	correlations sync.Map
	ownIPs       sync.Map
}

func New(serverURL string, token string) (*Client, error) {
	opts := &interactclient.Options{
		ServerURL: serverURL,
		Token:     token,
	}
	if strings.TrimSpace(serverURL) == "" {
		copied := *interactclient.DefaultOptions
		opts = &copied
		opts.Token = token
	}

	inner, err := interactclient.New(opts)
	if err != nil {
		return nil, err
	}

	return &Client{client: inner}, nil
}

func (c *Client) GeneratePayload(entry CorrelationEntry) string {
	url := c.client.URL()
	entry.FullOOBURL = url
	uniqueID := strings.Split(url, ".")[0]
	c.correlations.Store(uniqueID, entry)
	return url
}

func (c *Client) Load(uniqueID string) (CorrelationEntry, bool) {
	value, ok := c.correlations.Load(uniqueID)
	if !ok {
		return CorrelationEntry{}, false
	}
	entry, ok := value.(CorrelationEntry)
	return entry, ok
}

func (c *Client) Store(uniqueID string, entry CorrelationEntry) {
	c.correlations.Store(uniqueID, entry)
}

func (c *Client) Forget(uniqueID string) {
	c.correlations.Delete(uniqueID)
}

func (c *Client) StartPolling(interval time.Duration, callback func(*server.Interaction, CorrelationEntry, bool)) error {
	return c.client.StartPolling(interval, func(interaction *server.Interaction) {
		entry, ok := c.Load(interaction.UniqueID)
		callback(interaction, entry, ok)
	})
}

func (c *Client) DetectOwnIP(httpClient *http.Client) error {
	entry := CorrelationEntry{
		OwnIPProbe: true,
		SentAt:     time.Now().UTC(),
	}
	payload := c.GeneratePayload(entry)
	resp, err := httpClient.Get("https://" + payload)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Client) RememberOwnIP(remote string) {
	if remote == "" {
		return
	}
	c.ownIPs.Store(remote, true)
}

func (c *Client) IsOwnIP(remote string) bool {
	_, ok := c.ownIPs.Load(remote)
	return ok
}

func (c *Client) Stop() error {
	if err := c.client.StopPolling(); err != nil {
		return fmt.Errorf("stop polling: %w", err)
	}
	if err := c.client.Close(); err != nil {
		return fmt.Errorf("close client: %w", err)
	}
	return nil
}
