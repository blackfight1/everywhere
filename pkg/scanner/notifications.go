package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/blackfight1/everywhere/internal/database"
	"github.com/blackfight1/everywhere/pkg/notify"

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
		ResultsURL:       "",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	response, err := notify.SendFeishuCard(ctx, cfg.FeishuWebhook, alert)
	if err != nil {
		log.Printf("send feishu notification failed finding=%s err=%v response=%s", findingKey, err, response)
		return
	}
	log.Printf("feishu notification sent finding=%s confidence=%s evidence=%s response=%s", findingKey, confidence, evidence, response)

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

func (e *Engine) maybeNotifyResponseFinding(finding database.ResponseFinding) {
	cfg := e.cfg.Notification
	if !cfg.Enabled || strings.TrimSpace(cfg.FeishuWebhook) == "" {
		return
	}
	if !shouldNotifyConfidence(finding.Confidence) {
		return
	}

	findingKey := fmt.Sprintf("%s|%s|%s|%s", finding.ScanTaskID, finding.TargetURL, finding.PayloadType, finding.PayloadKey)
	var state database.NotificationState
	tx := e.db.First(&state, "finding_key = ?", findingKey)
	if tx.Error != nil && !errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		log.Printf("load response notification state failed: %v", tx.Error)
		return
	}

	kind := "initial"
	if tx.Error == nil {
		if notificationConfidenceRank[finding.Confidence] <= notificationConfidenceRank[state.Confidence] {
			return
		}
		kind = "upgrade"
	}

	alert := notify.FindingAlert{
		Title:            buildResponseNotificationTitle(finding.Confidence, kind),
		NotificationKind: kind,
		Severity:         finding.Severity,
		Confidence:       finding.Confidence,
		Evidence:         fmt.Sprintf("Response match via %s", finding.MatcherName),
		TargetURL:        finding.TargetURL,
		PayloadKey:       finding.PayloadKey,
		PayloadType:      finding.PayloadType,
		CallbackProtocol: "response",
		CallbackRemote:   finding.Upstream,
		TriggerMethod:    finding.RequestMethod,
		TriggerURL:       coalesceURL(finding.RequestURL, finding.TargetURL),
		TriggerStatus:    finding.ResponseStatus,
		ScanTaskID:       finding.ScanTaskID,
		OccurredAt:       finding.CreatedAt,
		TriggerPreview:   finding.RawRequest,
		ReplayPreview:    finding.ReplayCommand,
		ResultsURL:       "",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	response, err := notify.SendFeishuCard(ctx, cfg.FeishuWebhook, alert)
	if err != nil {
		log.Printf("send response finding feishu notification failed finding=%s err=%v response=%s", findingKey, err, response)
		return
	}
	log.Printf("feishu response finding notification sent finding=%s confidence=%s response=%s", findingKey, finding.Confidence, response)

	record := database.NotificationState{
		FindingKey:        findingKey,
		ScanTaskID:        finding.ScanTaskID,
		TargetURL:         finding.TargetURL,
		PayloadType:       finding.PayloadType,
		PayloadKey:        finding.PayloadKey,
		Confidence:        finding.Confidence,
		Evidence:          "response",
		LastProtocol:      "response",
		LastRemoteAddress: finding.Upstream,
		NotificationKind:  kind,
		LastNotifiedAt:    time.Now().UTC(),
	}
	if err := e.db.Save(&record).Error; err != nil {
		log.Printf("persist response notification state failed finding=%s err=%v", findingKey, err)
	}
}

func (e *Engine) maybeNotifyScanStarted(task database.ScanTask) {
	cfg := e.cfg.Notification
	if !cfg.Enabled || strings.TrimSpace(cfg.FeishuWebhook) == "" {
		return
	}

	alert := notify.BuildScanStartAlert(task.ID, task.Mode, task.TargetCount, "")
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	response, err := notify.SendFeishuLifecycleCard(ctx, cfg.FeishuWebhook, alert)
	if err != nil {
		log.Printf("send scan start notification failed task=%s err=%v response=%s", task.ID, err, response)
		return
	}
	log.Printf("scan start notification sent task=%s response=%s", task.ID, response)
}

func (e *Engine) maybeNotifyScanFinished(taskID string, status string) {
	cfg := e.cfg.Notification
	if !cfg.Enabled || strings.TrimSpace(cfg.FeishuWebhook) == "" {
		return
	}

	var task database.ScanTask
	if err := e.db.First(&task, "id = ?", taskID).Error; err != nil {
		log.Printf("load finished task for notification failed task=%s err=%v", taskID, err)
		return
	}

	alert := notify.BuildScanFinishedAlert(
		task.ID,
		task.Mode,
		task.TargetCount,
		task.RequestSent,
		task.PingbackCount,
		task.ResponseHitCount,
		status,
		"",
	)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	response, err := notify.SendFeishuLifecycleCard(ctx, cfg.FeishuWebhook, alert)
	if err != nil {
		log.Printf("send scan finish notification failed task=%s err=%v response=%s", taskID, err, response)
		return
	}
	log.Printf("scan finish notification sent task=%s response=%s", taskID, response)
}

func (e *Engine) maybeNotifyDispatchFinished(taskID string) {
	cfg := e.cfg.Notification
	if !cfg.Enabled || strings.TrimSpace(cfg.FeishuWebhook) == "" {
		return
	}

	var task database.ScanTask
	if err := e.db.First(&task, "id = ?", taskID).Error; err != nil {
		log.Printf("load dispatch-finished task for notification failed task=%s err=%v", taskID, err)
		return
	}

	alert := notify.BuildDispatchFinishedAlert(
		task.ID,
		task.Mode,
		task.TargetCount,
		task.RequestSent,
		task.PingbackCount,
		task.ResponseHitCount,
		"",
	)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	response, err := notify.SendFeishuLifecycleCard(ctx, cfg.FeishuWebhook, alert)
	if err != nil {
		log.Printf("send dispatch-finished notification failed task=%s err=%v response=%s", taskID, err, response)
		return
	}
	log.Printf("dispatch-finished notification sent task=%s response=%s", taskID, response)
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

func buildResponseNotificationTitle(confidence string, kind string) string {
	prefix := "[Everywhere]"
	switch {
	case confidence == "strong" && kind == "upgrade":
		return prefix + " Strong response finding upgraded"
	case confidence == "strong":
		return prefix + " Strong response finding"
	case kind == "upgrade":
		return prefix + " Confirmed response finding upgraded"
	default:
		return prefix + " Confirmed response finding"
	}
}

func coalesceURL(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}
