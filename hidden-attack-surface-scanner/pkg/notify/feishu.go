package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type FindingAlert struct {
	Title            string
	NotificationKind string
	Severity         string
	Confidence       string
	Evidence         string
	TargetURL        string
	PayloadKey       string
	PayloadType      string
	CallbackProtocol string
	CallbackRemote   string
	TriggerMethod    string
	TriggerURL       string
	TriggerStatus    *int
	ScanTaskID       string
	OccurredAt       time.Time
	TriggerPreview   string
	ReplayPreview    string
	ResultsURL       string
}

type webhookResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func SendFeishuCard(ctx context.Context, webhook string, alert FindingAlert) (string, error) {
	webhook = strings.TrimSpace(webhook)
	if webhook == "" {
		return "", fmt.Errorf("feishu webhook is empty")
	}

	payload := buildCardPayload(alert)

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal feishu payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build feishu request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send feishu request: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	result := strings.TrimSpace(string(raw))
	if resp.StatusCode >= 300 {
		return result, fmt.Errorf("feishu webhook returned status %d", resp.StatusCode)
	}

	if result != "" {
		var parsed webhookResponse
		if err := json.Unmarshal(raw, &parsed); err == nil && parsed.Code != 0 {
			return result, fmt.Errorf("feishu webhook rejected message: %s", parsed.Msg)
		}
	}

	return result, nil
}

func BuildTestAlert(frontendBaseURL string) FindingAlert {
	return FindingAlert{
		Title:            "[Everywhere] Feishu card test",
		NotificationKind: "test",
		Severity:         "high",
		Confidence:       "confirmed",
		Evidence:         "HTTP only",
		TargetURL:        "https://target.example/probe",
		PayloadKey:       "X-Forwarded-Host",
		PayloadType:      "header",
		CallbackProtocol: "http",
		CallbackRemote:   "203.0.113.10",
		TriggerMethod:    "GET",
		TriggerURL:       "https://target.example/probe",
		ScanTaskID:       "feishu-test-scan",
		OccurredAt:       time.Now().UTC(),
		TriggerPreview: "GET /probe HTTP/1.1\n" +
			"Host: target.example\n" +
			"X-Forwarded-Host: abc.oast.site\n" +
			"Cache-Control: no-transform",
		ReplayPreview: "curl --http1.1 -H 'X-Forwarded-Host: abc.oast.site' " +
			"'https://target.example/probe'",
		ResultsURL: buildResultsURL(frontendBaseURL, "feishu-test-scan"),
	}
}

func buildCardPayload(alert FindingAlert) map[string]any {
	elements := []any{
		map[string]any{
			"tag": "div",
			"text": map[string]any{
				"tag":     "lark_md",
				"content": buildSummaryMarkdown(alert),
			},
		},
		map[string]any{
			"tag": "div",
			"fields": []any{
				cardField("Target", truncateInline(alert.TargetURL, 220), false),
				cardField("Payload", fmt.Sprintf("%s (%s)", coalesce(alert.PayloadKey, "-"), coalesce(alert.PayloadType, "-")), true),
				cardField("Callback", fmt.Sprintf("%s from %s", strings.ToUpper(coalesce(alert.CallbackProtocol, "http")), coalesce(alert.CallbackRemote, "-")), true),
				cardField("Trigger", fmt.Sprintf("%s %s", coalesce(alert.TriggerMethod, "GET"), coalesce(alert.TriggerURL, alert.TargetURL)), false),
			},
		},
	}

	if alert.TriggerStatus != nil {
		elements = append(elements, map[string]any{
			"tag": "note",
			"elements": []any{
				map[string]any{
					"tag":     "plain_text",
					"content": fmt.Sprintf("Response status: %d", *alert.TriggerStatus),
				},
			},
		})
	}

	if preview := previewBlock(alert.TriggerPreview, 8, 700); preview != "" {
		elements = append(elements,
			map[string]any{"tag": "hr"},
			codeBlockElement("Trigger preview", preview),
		)
	}

	if replay := previewBlock(alert.ReplayPreview, 4, 700); replay != "" {
		elements = append(elements, codeBlockElement("Replay preview", replay))
	}

	elements = append(elements, map[string]any{
		"tag": "note",
		"elements": []any{
			map[string]any{
				"tag":     "plain_text",
				"content": fmt.Sprintf("Scan ID: %s", coalesce(alert.ScanTaskID, "-")),
			},
			map[string]any{
				"tag":     "plain_text",
				"content": fmt.Sprintf("Time: %s", alert.OccurredAt.Local().Format("2006-01-02 15:04:05 MST")),
			},
		},
	})

	if strings.TrimSpace(alert.ResultsURL) != "" {
		elements = append(elements,
			map[string]any{"tag": "hr"},
			map[string]any{
				"tag": "action",
				"actions": []any{
					map[string]any{
						"tag": "button",
						"text": map[string]any{
							"tag":     "plain_text",
							"content": "Open Results",
						},
						"type": "primary",
						"url":  strings.TrimSpace(alert.ResultsURL),
					},
				},
			},
		)
	}

	return map[string]any{
		"msg_type": "interactive",
		"card": map[string]any{
			"config": map[string]any{
				"wide_screen_mode": true,
				"enable_forward":   true,
			},
			"header": map[string]any{
				"template": cardTemplate(alert),
				"title": map[string]any{
					"tag":     "plain_text",
					"content": coalesce(alert.Title, "[Everywhere] OOB finding"),
				},
			},
			"elements": elements,
		},
	}
}

func titleWord(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func previewBlock(value string, maxLines int, maxChars int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if maxChars > 0 && len(value) > maxChars {
		value = value[:maxChars] + "...(truncated)"
	}
	if maxLines > 0 {
		lines := strings.Split(value, "\n")
		if len(lines) > maxLines {
			lines = append(lines[:maxLines], "...(truncated)")
			value = strings.Join(lines, "\n")
		}
	}
	return value
}

func coalesce(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func buildSummaryMarkdown(alert FindingAlert) string {
	lines := []string{
		fmt.Sprintf("**Type**: %s", escapeLarkMD(coalesce(alert.NotificationKind, "initial"))),
		fmt.Sprintf("**Severity**: %s", escapeLarkMD(strings.ToUpper(coalesce(alert.Severity, "high")))),
		fmt.Sprintf("**Confidence**: %s", escapeLarkMD(titleWord(coalesce(alert.Confidence, "confirmed")))),
		fmt.Sprintf("**Evidence**: %s", escapeLarkMD(coalesce(alert.Evidence, "HTTP only"))),
	}
	return strings.Join(lines, "\n")
}

func cardField(label string, value string, short bool) map[string]any {
	return map[string]any{
		"is_short": short,
		"text": map[string]any{
			"tag": "lark_md",
			"content": fmt.Sprintf("**%s**\n%s",
				escapeLarkMD(label),
				escapeLarkMD(coalesce(value, "-")),
			),
		},
	}
}

func codeBlockElement(label string, value string) map[string]any {
	return map[string]any{
		"tag": "div",
		"text": map[string]any{
			"tag": "lark_md",
			"content": fmt.Sprintf("**%s**\n```text\n%s\n```",
				escapeLarkMD(label),
				sanitizeCodeFence(value),
			),
		},
	}
}

func cardTemplate(alert FindingAlert) string {
	switch {
	case strings.EqualFold(alert.NotificationKind, "test"):
		return "blue"
	case strings.EqualFold(alert.Confidence, "strong"):
		return "red"
	case strings.EqualFold(alert.Confidence, "confirmed"):
		return "orange"
	default:
		return "grey"
	}
}

func buildResultsURL(frontendBaseURL string, scanTaskID string) string {
	base := strings.TrimRight(strings.TrimSpace(frontendBaseURL), "/")
	if base == "" || strings.TrimSpace(scanTaskID) == "" {
		return ""
	}
	return base + "/results?scan_task_id=" + scanTaskID
}

func truncateInline(value string, max int) string {
	value = strings.TrimSpace(value)
	if max > 0 && len(value) > max {
		return value[:max] + "...(truncated)"
	}
	return value
}

func sanitizeCodeFence(value string) string {
	value = strings.ReplaceAll(value, "```", "` ` `")
	return strings.TrimSpace(value)
}

func escapeLarkMD(value string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"*", "\\*",
		"_", "\\_",
		"[", "\\[",
		"]", "\\]",
		"(", "\\(",
		")", "\\)",
	)
	return replacer.Replace(strings.TrimSpace(value))
}
