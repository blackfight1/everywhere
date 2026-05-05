package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/blackfight1/everywhere/internal/database"

	"gorm.io/gorm"
)

const proxyLocalSSHPayloadKey = "proxy-local-ssh"

var defaultProxyUnsafeMethods = []string{"GET", "POST", "OPTIONS", "TRACE", "CONNECT"}
var defaultProxyUnsafeUpstreams = []string{"127.0.0.1:22", "localhost:22"}

type proxyUnsafeMatch struct {
	Matched     bool
	Confidence  string
	Severity    string
	MatcherName string
}

func proxyUnsafeVariants() []ProxyUnsafeVariant {
	var variants []ProxyUnsafeVariant
	for _, method := range defaultProxyUnsafeMethods {
		for _, upstream := range defaultProxyUnsafeUpstreams {
			variants = append(variants, ProxyUnsafeVariant{
				Method:   method,
				Upstream: upstream,
			})
		}
	}
	return variants
}

func proxyUnsafeVariantKey(variant ProxyUnsafeVariant) string {
	return fmt.Sprintf("%s|%s", strings.ToLower(variant.Method), variant.Upstream)
}

func evaluateProxyUnsafeResponse(variant ProxyUnsafeVariant, resp RawResponse) proxyUnsafeMatch {
	body := strings.ToLower(resp.BodyExcerpt)
	raw := strings.ToLower(resp.RawExcerpt)

	hasProtocolMismatch := strings.Contains(body, "protocol mismatch") || strings.Contains(raw, "protocol mismatch")
	hasOpenSSH := strings.Contains(body, "openssh") || strings.Contains(raw, "openssh")
	hasSSHBanner := strings.Contains(body, "ssh-2.0-") || strings.Contains(raw, "ssh-2.0-")

	switch {
	case resp.StatusCode == 200 && hasProtocolMismatch && hasOpenSSH:
		return proxyUnsafeMatch{Matched: true, Confidence: "strong", Severity: "high", MatcherName: "status-200-protocol-mismatch-openssh"}
	case hasSSHBanner && hasOpenSSH:
		return proxyUnsafeMatch{Matched: true, Confidence: "strong", Severity: "high", MatcherName: "ssh-banner-openssh"}
	default:
		return proxyUnsafeMatch{}
	}
}

func (e *Engine) sendProxyUnsafeTarget(
	ctx context.Context,
	taskID string,
	target string,
	totalRequests int,
) (bool, error) {
	for _, variant := range proxyUnsafeVariants() {
		if err := e.sendSingleProxyUnsafeVariant(ctx, taskID, target, variant, totalRequests); err != nil {
			if finding, ok := err.(proxyUnsafeStopError); ok {
				return finding.StrongMatch, nil
			}
			return false, err
		}
	}
	return false, nil
}

type proxyUnsafeStopError struct {
	StrongMatch bool
}

func (e proxyUnsafeStopError) Error() string {
	return "proxy-local-ssh strong match found"
}

func (e *Engine) sendSingleProxyUnsafeVariant(
	ctx context.Context,
	taskID string,
	target string,
	variant ProxyUnsafeVariant,
	totalRequests int,
) error {
	rawRequest, err := BuildProxyUnsafeRequest(target, variant)
	if err != nil {
		return nil
	}

	snapshot := BuildRawRequestSnapshot(target, rawRequest)
	uniqueID := fmt.Sprintf("response:%s:%s:%s", taskID, firstLabel(strings.ToLower(variant.Method)), strings.ReplaceAll(variant.Upstream, ":", "_"))
	sent := database.SentPayload{
		UniqueID:      uniqueID + ":" + fmt.Sprintf("%d", time.Now().UnixNano()),
		ScanTaskID:    taskID,
		TargetURL:     target,
		PayloadType:   "raw",
		PayloadKey:    proxyLocalSSHPayloadKey,
		PayloadValue:  string(rawRequest.RawBytes),
		RequestMethod: snapshot.Method,
		RequestURL:    snapshot.URL,
		RawRequest:    snapshot.RawRequest,
		ReplayCommand: snapshot.ReplayCommand,
		SentAt:        time.Now().UTC(),
	}
	if err := e.db.Create(&sent).Error; err != nil {
		return err
	}

	resp, sendErr := SendRawRequestDetailed(ctx, rawRequest, 15*time.Second)
	e.incrementRequestCount(taskID, totalRequests)
	if sendErr != nil {
		return nil
	}

	if resp.StatusCode > 0 {
		_ = e.db.Model(&database.SentPayload{}).Where("unique_id = ?", sent.UniqueID).Update("response_status", resp.StatusCode).Error
	}

	match := evaluateProxyUnsafeResponse(variant, resp)
	if !match.Matched {
		return nil
	}

	finding := database.ResponseFinding{
		ScanTaskID:          taskID,
		TargetURL:           target,
		PayloadType:         "raw",
		PayloadKey:          proxyLocalSSHPayloadKey,
		VariantKey:          proxyUnsafeVariantKey(variant),
		RequestMethod:       snapshot.Method,
		RequestURL:          snapshot.URL,
		RawRequest:          snapshot.RawRequest,
		ReplayCommand:       snapshot.ReplayCommand,
		ResponseStatus:      intPtr(resp.StatusCode),
		ResponseHeaders:     headerString(resp.Headers),
		ResponseBodyExcerpt: resp.BodyExcerpt,
		MatcherName:         match.MatcherName,
		Severity:            match.Severity,
		Confidence:          match.Confidence,
		Upstream:            variant.Upstream,
	}
	if err := e.db.Where("scan_task_id = ? AND target_url = ? AND payload_key = ? AND variant_key = ?",
		finding.ScanTaskID, finding.TargetURL, finding.PayloadKey, finding.VariantKey).
		FirstOrCreate(&finding).Error; err != nil {
		return err
	}

	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).UpdateColumn("response_hit_count", gorm.Expr("response_hit_count + 1"))
	e.maybeNotifyResponseFinding(finding)
	e.broadcast(map[string]any{
		"type":    "response_finding",
		"task_id": taskID,
		"data":    finding,
	})

	if match.Confidence == "strong" {
		return proxyUnsafeStopError{StrongMatch: true}
	}
	return nil
}

func intPtr(value int) *int {
	if value == 0 {
		return nil
	}
	result := value
	return &result
}
