package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	appconfig "hidden-attack-surface-scanner/internal/config"
	"hidden-attack-surface-scanner/internal/database"
	"hidden-attack-surface-scanner/pkg/notify"

	"gorm.io/gorm"
)

var notificationConfidenceRank = map[string]int{
	"observed":  0,
	"possible":  1,
	"confirmed": 2,
	"strong":    3,
}

func (e *Engine) maybeNotifyFinding(pingback database.Pingback) {
	cfg := e.cfg.Notification
	if !cfg.Enabled || strings.TrimSpace(cfg.FeishuWebhook) == "" || pingback.FromOwnIP {
		return
	}

	findingKey := buildFindingKey(pingback)
	protocols, err := e.findingProtocols(pingback)
	if err != nil {
		log.Printf("load finding protocols failed: %v", err)
		return
	}

	confidence, evidence := summarizeFindingEvidence(protocols)
	if !shouldNotifyConfidence(confidence) {
		return
	}

	var state database.NotificationState
	tx := e.db.First(&state, "finding_key = ?", findingKey)
	if tx.Error != nil && !errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		log.Printf("load notification state failed: %v", tx.Error)
		return
	}

	kind := "initial"
	if tx.Error == nil {
		if notificationConfidenceRank[confidence] <= notificationConfidenceRank[state.Confidence] {
			return
		}
		kind = "upgrade"
	}

	var sent database.SentPayload
	if err := e.db.First(&sent, "unique_id = ?", pingback.UniqueID).Error; err != nil {
		log.Printf("load sent payload for notification failed: %v", err)
		return
	}

	alert := notify.FindingAlert{
		Title:            buildNotificationTitle(confidence, kind),
		NotificationKind: kind,
		Severity:         pingback.Severity,
		Confidence:       confidence,
		Evidence:         evidence,
		TargetURL:        pingback.TargetURL,
		PayloadKey:       pingback.PayloadKey,
		PayloadType:      pingback.PayloadType,
		CallbackProtocol: pingback.CallbackProtocol,
		CallbackRemote:   pingback.RemoteAddress,
		TriggerMethod:    sent.RequestMethod,
		TriggerURL:       coalesceURL(sent.RequestURL, pingback.TargetURL),
		TriggerStatus:    sent.ResponseStatus,
		ScanTaskID:       pingback.ScanTaskID,
		OccurredAt:       pingback.ReceivedAt,
		TriggerPreview:   sent.RawRequest,
		ReplayPreview:    sent.ReplayCommand,
		ResultsURL:       buildResultsURL(cfg, pingback.ScanTaskID),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	response, err := notify.SendFeishuCard(ctx, cfg.FeishuWebhook, alert)
	if err != nil {
		log.Printf("send feishu notification failed finding=%s err=%v response=%s", findingKey, err, response)
		return
	}

	record := database.NotificationState{
		FindingKey:        findingKey,
		ScanTaskID:        pingback.ScanTaskID,
		TargetURL:         pingback.TargetURL,
		PayloadType:       pingback.PayloadType,
		PayloadKey:        pingback.PayloadKey,
		Confidence:        confidence,
		Evidence:          evidence,
		LastProtocol:      pingback.CallbackProtocol,
		LastRemoteAddress: pingback.RemoteAddress,
		NotificationKind:  kind,
		LastNotifiedAt:    time.Now().UTC(),
	}
	if err := e.db.Save(&record).Error; err != nil {
		log.Printf("persist notification state failed finding=%s err=%v", findingKey, err)
	}
}

func (e *Engine) findingProtocols(pingback database.Pingback) ([]string, error) {
	var rows []string
	if err := e.db.Model(&database.Pingback{}).
		Distinct("callback_protocol").
		Where("scan_task_id = ? AND target_url = ? AND payload_type = ? AND payload_key = ?",
			pingback.ScanTaskID, pingback.TargetURL, pingback.PayloadType, pingback.PayloadKey).
		Pluck("callback_protocol", &rows).Error; err != nil {
		return nil, err
	}

	protocols := make([]string, 0, len(rows))
	for _, row := range rows {
		value := strings.ToLower(strings.TrimSpace(row))
		if value != "" {
			protocols = append(protocols, value)
		}
	}
	return protocols, nil
}

func summarizeFindingEvidence(protocols []string) (string, string) {
	hasDNS := false
	hasWeb := false
	hasHTTPS := false
	for _, protocol := range protocols {
		switch strings.ToLower(strings.TrimSpace(protocol)) {
		case "dns":
			hasDNS = true
		case "http":
			hasWeb = true
		case "https":
			hasWeb = true
			hasHTTPS = true
		}
	}

	switch {
	case hasDNS && hasWeb:
		if hasHTTPS {
			return "strong", "DNS + HTTPS"
		}
		return "strong", "DNS + HTTP"
	case hasWeb:
		if hasHTTPS {
			return "confirmed", "HTTPS only"
		}
		return "confirmed", "HTTP only"
	case hasDNS:
		return "possible", "DNS only"
	default:
		return "observed", "Observed"
	}
}

func shouldNotifyConfidence(confidence string) bool {
	return confidence == "confirmed" || confidence == "strong"
}

func buildFindingKey(pingback database.Pingback) string {
	return fmt.Sprintf("%s|%s|%s|%s", pingback.ScanTaskID, pingback.TargetURL, pingback.PayloadType, pingback.PayloadKey)
}

func buildNotificationTitle(confidence string, kind string) string {
	prefix := "[Everywhere]"
	switch {
	case confidence == "strong" && kind == "upgrade":
		return prefix + " Strong OOB finding upgraded"
	case confidence == "strong":
		return prefix + " Strong OOB finding"
	case kind == "upgrade":
		return prefix + " Confirmed OOB finding upgraded"
	default:
		return prefix + " Confirmed OOB finding"
	}
}

func buildResultsURL(cfg appconfig.NotificationConfig, scanTaskID string) string {
	base := strings.TrimRight(strings.TrimSpace(cfg.FrontendBaseURL), "/")
	if base == "" || strings.TrimSpace(scanTaskID) == "" {
		return ""
	}

	values := url.Values{}
	values.Set("scan_task_id", scanTaskID)
	return base + "/results?" + values.Encode()
}

func coalesceURL(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}
