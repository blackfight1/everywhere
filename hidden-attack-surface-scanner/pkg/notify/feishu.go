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
	Title              string
	NotificationKind   string
	Severity           string
	Confidence         string
	Evidence           string
	TargetURL          string
	PayloadKey         string
	PayloadType        string
	CallbackProtocol   string
	CallbackRemote     string
	TriggerMethod      string
	TriggerURL         string
	TriggerStatus      *int
	ScanTaskID         string
	OccurredAt         time.Time
	TriggerPreview     string
	ReplayPreview      string
	ResultsURL         string
}

type webhookResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func SendFeishuText(ctx context.Context, webhook string, alert FindingAlert) (string, error) {
	webhook = strings.TrimSpace(webhook)
	if webhook == "" {
		return "", fmt.Errorf("feishu webhook is empty")
	}

	payload := map[string]any{
		"msg_type": "text",
		"content": map[string]string{
			"text": buildText(alert),
		},
	}

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
		Title:            "[Everywhere] Feishu test notification",
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
		ResultsURL: strings.TrimRight(strings.TrimSpace(frontendBaseURL), "/") + "/results?scan_task_id=feishu-test-scan",
	}
}

func buildText(alert FindingAlert) string {
	lines := []string{
		coalesce(alert.Title, "[Everywhere] OOB finding"),
		fmt.Sprintf("Type: %s", coalesce(alert.NotificationKind, "initial")),
		fmt.Sprintf("Severity: %s", strings.ToUpper(coalesce(alert.Severity, "high"))),
		fmt.Sprintf("Confidence: %s", titleWord(coalesce(alert.Confidence, "confirmed"))),
		fmt.Sprintf("Evidence: %s", coalesce(alert.Evidence, "HTTP only")),
		fmt.Sprintf("Target: %s", coalesce(alert.TargetURL, "-")),
		fmt.Sprintf("Payload: %s (%s)", coalesce(alert.PayloadKey, "-"), coalesce(alert.PayloadType, "-")),
		fmt.Sprintf("Callback: %s from %s", strings.ToUpper(coalesce(alert.CallbackProtocol, "http")), coalesce(alert.CallbackRemote, "-")),
		fmt.Sprintf("Trigger: %s %s", coalesce(alert.TriggerMethod, "GET"), coalesce(alert.TriggerURL, alert.TargetURL)),
	}

	if alert.TriggerStatus != nil {
		lines = append(lines, fmt.Sprintf("Response: %d", *alert.TriggerStatus))
	}
	lines = append(lines,
		fmt.Sprintf("Scan ID: %s", coalesce(alert.ScanTaskID, "-")),
		fmt.Sprintf("Time: %s", alert.OccurredAt.Local().Format("2006-01-02 15:04:05 MST")),
	)

	triggerPreview := previewBlock(alert.TriggerPreview, 8, 700)
	if triggerPreview != "" {
		lines = append(lines, "", "Trigger preview:", triggerPreview)
	}

	replayPreview := previewBlock(alert.ReplayPreview, 4, 700)
	if replayPreview != "" {
		lines = append(lines, "", "Replay preview:", replayPreview)
	}

	if strings.TrimSpace(alert.ResultsURL) != "" {
		lines = append(lines, "", "Results:", strings.TrimSpace(alert.ResultsURL))
	}

	return strings.Join(lines, "\n")
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
