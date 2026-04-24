package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	appconfig "hidden-attack-surface-scanner/internal/config"
	"hidden-attack-surface-scanner/internal/database"
	"hidden-attack-surface-scanner/pkg/correlator"
	"hidden-attack-surface-scanner/pkg/notify"
	"hidden-attack-surface-scanner/pkg/oob"
	"hidden-attack-surface-scanner/pkg/payload"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

type Broadcaster interface {
	Broadcast(any)
}

const (
	scanModeQuick = "quick"
	scanModeFull  = "full"
)

var quickRawPayloadKeys = map[string]struct{}{
	"absolute-url-host-mismatch": {},
	"duplicate-host":             {},
	"sni-host-mismatch":          {},
	"sni-host-mismatch-reversed": {},
	"host-at-reversed":           {},
	"host-with-at":               {},
}

type StartScanRequest struct {
	Targets                []string          `json:"targets"`
	Mode                   string            `json:"mode"`
	Concurrency            int               `json:"concurrency"`
	BatchSize              int               `json:"batch_size"`
	RateLimit              int               `json:"rate_limit"`
	CallbackTimeoutMinutes int               `json:"callback_timeout_minutes"`
	Proxy                  string            `json:"proxy"`
	InteractshServer       string            `json:"interactsh_server"`
	InteractshToken        string            `json:"interactsh_token"`
	CustomHeaders          map[string]string `json:"custom_headers"`
	AltPorts               []int             `json:"alt_ports"`
	ScopeFilter            ScopeFilter       `json:"scope_filter"`
	DefaultOrigin          string            `json:"default_origin"`
	DefaultReferer         string            `json:"default_referer"`
}

type ScopeFilter struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

type Engine struct {
	db          *gorm.DB
	cfg         appconfig.Config
	broadcaster Broadcaster
	mu          sync.Mutex
	running     map[string]context.CancelFunc
}

func NewEngine(db *gorm.DB, cfg appconfig.Config, broadcaster Broadcaster) *Engine {
	return &Engine{
		db:          db,
		cfg:         cfg,
		broadcaster: broadcaster,
		running:     make(map[string]context.CancelFunc),
	}
}

func (e *Engine) StartScan(req StartScanRequest) (*database.ScanTask, error) {
	req.applyDefaults(e.cfg)
	if !isSupportedScanMode(req.Mode) {
		return nil, fmt.Errorf("unsupported scan mode: %s", req.Mode)
	}
	if len(req.Targets) == 0 {
		return nil, errors.New("targets cannot be empty")
	}

	filteredTargets := filterTargets(req.Targets, req.ScopeFilter)
	if len(filteredTargets) == 0 {
		return nil, errors.New("no targets remain after scope filtering")
	}
	req.Targets = filteredTargets

	configJSON, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	task := &database.ScanTask{
		Status:       "pending",
		Mode:         strings.ToLower(req.Mode),
		Config:       string(configJSON),
		TargetCount:  len(req.Targets),
		BatchSize:    req.BatchSize,
		BatchCount:   batchCount(len(req.Targets), req.BatchSize),
		CurrentStage: "queued",
	}
	if err := e.db.Create(task).Error; err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.running[task.ID] = cancel
	e.mu.Unlock()

	go e.runTask(ctx, task.ID, req)
	return task, nil
}

func (e *Engine) StopScan(taskID string) error {
	e.mu.Lock()
	cancel, ok := e.running[taskID]
	e.mu.Unlock()
	if !ok {
		return fmt.Errorf("scan task not running: %s", taskID)
	}
	cancel()
	return nil
}

func (e *Engine) runTask(ctx context.Context, taskID string, req StartScanRequest) {
	defer func() {
		if recovered := recover(); recovered != nil {
			e.failTask(taskID, fmt.Errorf("panic: %v", recovered), string(debug.Stack()))
		}
		e.clearTask(taskID)
	}()

	now := time.Now().UTC()
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
		"status":        "running",
		"started_at":    now,
		"last_error":    "",
		"current_stage": "preparing",
	})
	e.broadcast(map[string]any{
		"type":    "task_status",
		"task_id": taskID,
		"scan_id": taskID,
		"status":  "running",
	})

	client, err := oob.New(req.InteractshServer, req.InteractshToken)
	if err != nil {
		e.failTask(taskID, err, "")
		return
	}
	defer client.Stop()

	e.broadcastLog(taskID, "info", "Initializing HTTP client...")
	httpClient, err := NewHTTPClient(req.Proxy, 15*time.Second)
	if err != nil {
		e.failTask(taskID, err, "")
		return
	}

	e.broadcastLog(taskID, "info", "Starting OOB interaction polling (interval=5s)...")
	if err := client.StartPolling(5*time.Second, func(interaction *server.Interaction, entry oob.CorrelationEntry, ok bool) {
		e.handleInteraction(taskID, client, interaction, entry, ok)
	}); err != nil {
		e.failTask(taskID, err, "")
		return
	}

	e.broadcastLog(taskID, "info", "Detecting own IP via interactsh...")
	if err := client.DetectOwnIP(httpClient); err != nil {
		e.broadcastLog(taskID, "warn", fmt.Sprintf("Own-IP detection failed (callbacks from own IP will not be filtered): %v", err))
	}

	e.broadcastLog(taskID, "info", fmt.Sprintf("Loading payloads for mode=%s...", req.Mode))
	items, err := e.loadPayloads(req.Mode)
	if err != nil {
		e.failTask(taskID, err, "")
		return
	}
	e.broadcastLog(taskID, "info", fmt.Sprintf("Loaded %d payloads, dispatching to %d targets (concurrency=%d, rate_limit=%d)...",
		len(items), len(req.Targets), req.Concurrency, req.RateLimit))
	totalRequests := estimateTotalRequests(req, items)
	batches := chunkTargets(req.Targets, req.BatchSize)
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Update("estimated_requests", totalRequests)
	e.broadcastProgress(taskID, 0, totalRequests)
	e.broadcastLog(taskID, "info", fmt.Sprintf("Split %d targets into %d batch(es) with batch_size=%d.", len(req.Targets), len(batches), req.BatchSize))

	for idx, targets := range batches {
		batchIndex := idx + 1
		e.broadcastLog(taskID, "info", fmt.Sprintf("Batch %d/%d started (%d targets).", batchIndex, len(batches), len(targets)))
		e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
			"current_batch": batchIndex,
			"current_stage": "dispatching",
		})
		e.broadcastProgress(taskID, 0, totalRequests)

		if err := e.dispatch(ctx, taskID, req, client, httpClient, targets, items, totalRequests, batchIndex, len(batches)); err != nil && !errors.Is(err, context.Canceled) {
			e.failTask(taskID, err, "")
			return
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			break
		}
		e.broadcastLog(taskID, "info", fmt.Sprintf("Batch %d/%d dispatched.", batchIndex, len(batches)))
	}

	if errors.Is(ctx.Err(), context.Canceled) {
		e.finishTask(taskID, "stopped")
		return
	}

	e.broadcastLog(taskID, "info", fmt.Sprintf("All requests dispatched. Waiting for OOB callbacks (timeout=%dm)...", req.CallbackTimeoutMinutes))
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
		"status":         "waiting_callback",
		"current_target": "",
		"current_stage":  "waiting_callback",
	})
	e.broadcast(map[string]any{
		"type":    "task_status",
		"task_id": taskID,
		"scan_id": taskID,
		"status":  "waiting_callback",
	})

	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(req.CallbackTimeoutMinutes)*time.Minute)
	defer cancel()
	<-waitCtx.Done()
	if errors.Is(ctx.Err(), context.Canceled) {
		e.finishTask(taskID, "stopped")
		return
	}

	e.finishTask(taskID, "completed")
}

func (e *Engine) dispatch(
	ctx context.Context,
	taskID string,
	req StartScanRequest,
	client *oob.Client,
	httpClient *http.Client,
	targets []string,
	items []payload.Payload,
	totalRequests int,
	batchIndex int,
	batchTotal int,
) error {
	limiter := rate.NewLimiter(rate.Inf, 1)
	if req.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(req.RateLimit), 1)
	}

	jobs := make(chan func() error)
	var wg sync.WaitGroup
	errCh := make(chan error, 1)

	workerCount := req.Concurrency
	if workerCount < 1 {
		workerCount = 1
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if err := job(); err != nil && !errors.Is(err, context.Canceled) {
					select {
					case errCh <- err:
					default:
					}
				}
			}
		}()
	}

	standardPayloads := filterPayloadsByType(items, payload.TypeHeader, payload.TypeParam)
	standardPayloads, hostPayloads := splitHostPayloads(standardPayloads)
	rawPayloads := filterPayloadsByType(items, payload.TypeRaw)

enqueueLoop:
	for idx, target := range targets {
		target := target
		targetOrdinal := idx + 1
		select {
		case jobs <- func() error {
			return e.scanTarget(ctx, taskID, req, client, httpClient, limiter, target, standardPayloads, hostPayloads, rawPayloads, totalRequests, batchIndex, batchTotal, targetOrdinal, len(targets))
		}:
		case <-ctx.Done():
			break enqueueLoop
		}
	}

	close(jobs)
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return ctx.Err()
	}
}

func (e *Engine) scanTarget(
	ctx context.Context,
	taskID string,
	req StartScanRequest,
	client *oob.Client,
	httpClient *http.Client,
	limiter *rate.Limiter,
	target string,
	standardPayloads []payload.Payload,
	hostPayloads []payload.Payload,
	rawPayloads []payload.Payload,
	totalRequests int,
	batchIndex int,
	batchTotal int,
	targetOrdinal int,
	batchTargetCount int,
) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	e.setTaskActivity(taskID, batchIndex, target, fmt.Sprintf("target %d/%d", targetOrdinal, batchTargetCount), totalRequests)
	e.broadcastLog(taskID, "debug", fmt.Sprintf("Batch %d/%d target %d/%d started: %s", batchIndex, batchTotal, targetOrdinal, batchTargetCount, target))

	if len(standardPayloads) > 0 {
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
		e.setTaskActivity(taskID, batchIndex, target, "standard-headers", totalRequests)
		e.broadcastLog(taskID, "debug", fmt.Sprintf("Batch %d/%d target %d/%d standard headers dispatched: %s", batchIndex, batchTotal, targetOrdinal, batchTargetCount, target))
		if err := e.sendStandardTarget(ctx, taskID, req, client, httpClient, target, standardPayloads, totalRequests); err != nil {
			return err
		}
	}

	if len(hostPayloads) > 0 {
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
		e.setTaskActivity(taskID, batchIndex, target, "host-only", totalRequests)
		e.broadcastLog(taskID, "debug", fmt.Sprintf("Batch %d/%d target %d/%d host-only dispatched: %s", batchIndex, batchTotal, targetOrdinal, batchTargetCount, target))
		if err := e.sendStandardTarget(ctx, taskID, req, client, httpClient, target, hostPayloads, totalRequests); err != nil {
			return err
		}
	}

	for _, rawPayload := range rawPayloads {
		if rawPayload.Key == "alt-ports" {
			continue
		}
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
		e.setTaskActivity(taskID, batchIndex, target, "raw-"+rawPayload.Key, totalRequests)
		e.broadcastLog(taskID, "debug", fmt.Sprintf("Batch %d/%d target %d/%d raw %s dispatched: %s", batchIndex, batchTotal, targetOrdinal, batchTargetCount, rawPayload.Key, target))
		if err := e.sendRawTarget(ctx, taskID, req, client, target, rawPayload, totalRequests); err != nil {
			return err
		}
	}

	for _, altTarget := range buildAltTargets(target, req.AltPorts) {
		if len(standardPayloads) > 0 {
			if err := limiter.Wait(ctx); err != nil {
				return err
			}
			e.setTaskActivity(taskID, batchIndex, altTarget, "alt-port-standard", totalRequests)
			if err := e.sendStandardTarget(ctx, taskID, req, client, httpClient, altTarget, standardPayloads, totalRequests); err != nil {
				return err
			}
		}
		if len(hostPayloads) > 0 {
			if err := limiter.Wait(ctx); err != nil {
				return err
			}
			e.setTaskActivity(taskID, batchIndex, altTarget, "alt-port-host-only", totalRequests)
			if err := e.sendStandardTarget(ctx, taskID, req, client, httpClient, altTarget, hostPayloads, totalRequests); err != nil {
				return err
			}
		}
	}

	e.markTargetCompleted(taskID, batchIndex, totalRequests)
	e.broadcastLog(taskID, "debug", fmt.Sprintf("Batch %d/%d target %d/%d completed: %s", batchIndex, batchTotal, targetOrdinal, batchTargetCount, target))
	return nil
}

func (e *Engine) sendStandardTarget(
	ctx context.Context,
	taskID string,
	req StartScanRequest,
	client *oob.Client,
	httpClient *http.Client,
	target string,
	items []payload.Payload,
	totalRequests int,
) error {
	parsed, err := url.Parse(target)
	if err != nil {
		return err
	}

	resolveOpts := payload.ResolveOptions{
		Host:           parsed.Hostname(),
		DefaultOrigin:  req.DefaultOrigin,
		DefaultReferer: req.DefaultReferer,
	}

	resolved := make([]payload.ResolvedPayload, 0, len(items))
	uniqueIDs := make([]string, 0, len(items))
	sentRows := make([]database.SentPayload, 0, len(items))
	sentAt := time.Now().UTC()

	for _, item := range items {
		if !canResolvePayload(item, resolveOpts) {
			continue
		}
		entry := oob.CorrelationEntry{
			ScanTaskID:  taskID,
			TargetURL:   target,
			PayloadType: string(item.Type),
			PayloadKey:  item.Key,
			SentAt:      sentAt,
		}
		oobURL := client.GeneratePayload(entry)
		resolvedItem, ok := payload.Resolve(item, oobURL, resolveOpts)
		if !ok {
			continue
		}

		uniqueID := firstLabel(oobURL)
		entry.PayloadVal = resolvedItem.ResolvedValue
		client.Store(uniqueID, entry)
		uniqueIDs = append(uniqueIDs, uniqueID)
		sentRows = append(sentRows, database.SentPayload{
			UniqueID:     uniqueID,
			ScanTaskID:   taskID,
			TargetURL:    target,
			PayloadType:  string(item.Type),
			PayloadKey:   item.Key,
			PayloadValue: resolvedItem.ResolvedValue,
			SentAt:       sentAt,
		})
		resolved = append(resolved, resolvedItem)
	}

	if len(resolved) == 0 {
		return nil
	}
	triggerReq, err := BuildStandardRequest(ctx, target, resolved, req.CustomHeaders)
	if err != nil {
		return err
	}
	snapshot, err := CaptureRequestSnapshot(triggerReq)
	if err != nil {
		return err
	}
	for idx := range sentRows {
		sentRows[idx].RequestMethod = snapshot.Method
		sentRows[idx].RequestURL = snapshot.URL
		sentRows[idx].RawRequest = snapshot.RawRequest
		sentRows[idx].ReplayCommand = snapshot.ReplayCommand
	}
	if err := e.db.Create(&sentRows).Error; err != nil {
		return err
	}

	statusCode, err := SendPreparedRequest(httpClient, triggerReq)
	if err != nil {
		log.Printf("send standard request failed target=%s err=%v", target, err)
		e.incrementRequestCount(taskID, totalRequests)
		return nil
	}

	e.incrementRequestCount(taskID, totalRequests)
	if len(uniqueIDs) > 0 {
		e.db.Model(&database.SentPayload{}).Where("unique_id IN ?", uniqueIDs).Update("response_status", statusCode)
	}
	return nil
}

func (e *Engine) sendRawTarget(
	ctx context.Context,
	taskID string,
	req StartScanRequest,
	client *oob.Client,
	target string,
	item payload.Payload,
	totalRequests int,
) error {
	entry := oob.CorrelationEntry{
		ScanTaskID:  taskID,
		TargetURL:   target,
		PayloadType: string(item.Type),
		PayloadKey:  item.Key,
		SentAt:      time.Now().UTC(),
	}
	oobURL := client.GeneratePayload(entry)
	rawRequest, err := BuildCrackingRequest(target, item, oobURL)
	if err != nil {
		client.Forget(firstLabel(oobURL))
		log.Printf("skip raw payload %s for %s: %v", item.Key, target, err)
		return nil
	}

	uniqueID := firstLabel(oobURL)
	entry.PayloadVal = string(rawRequest.RawBytes)
	client.Store(uniqueID, entry)
	snapshot := BuildRawRequestSnapshot(target, rawRequest)
	sent := database.SentPayload{
		UniqueID:      uniqueID,
		ScanTaskID:    taskID,
		TargetURL:     target,
		PayloadType:   string(item.Type),
		PayloadKey:    item.Key,
		PayloadValue:  string(rawRequest.RawBytes),
		RequestMethod: snapshot.Method,
		RequestURL:    snapshot.URL,
		RawRequest:    snapshot.RawRequest,
		ReplayCommand: snapshot.ReplayCommand,
		SentAt:        entry.SentAt,
	}
	if err := e.db.Create(&sent).Error; err != nil {
		return err
	}

	statusCode, err := SendRawRequest(ctx, rawRequest, 15*time.Second)
	e.incrementRequestCount(taskID, totalRequests)
	if err != nil {
		return nil
	}
	return e.db.Model(&database.SentPayload{}).Where("unique_id = ?", uniqueID).Update("response_status", statusCode).Error
}

func (e *Engine) handleInteraction(
	taskID string,
	client *oob.Client,
	interaction *server.Interaction,
	entry oob.CorrelationEntry,
	ok bool,
) {
	if interaction == nil || interaction.UniqueID == "" {
		return
	}

	protocol := strings.ToLower(strings.TrimSpace(interaction.Protocol))
	if exists, _ := e.pingbackExists(interaction.UniqueID, protocol); exists {
		return
	}

	if ok && entry.OwnIPProbe {
		client.RememberOwnIP(normalizeRemoteAddress(interaction.RemoteAddress))
		client.Forget(interaction.UniqueID)
		return
	}

	if !ok {
		var sent database.SentPayload
		tx := e.db.Limit(1).Find(&sent, "unique_id = ?", interaction.UniqueID)
		if tx.Error != nil {
			return
		}
		if tx.RowsAffected == 0 {
			return
		}
		entry = oob.CorrelationEntry{
			ScanTaskID:  sent.ScanTaskID,
			TargetURL:   sent.TargetURL,
			PayloadType: sent.PayloadType,
			PayloadKey:  sent.PayloadKey,
			PayloadVal:  sent.PayloadValue,
			SentAt:      sent.SentAt,
		}
	} else if strings.TrimSpace(entry.PayloadVal) == "" {
		var sent database.SentPayload
		tx := e.db.Limit(1).Find(&sent, "unique_id = ?", interaction.UniqueID)
		if tx.Error != nil {
			return
		}
		if tx.RowsAffected == 0 {
			return
		}
		entry.PayloadVal = sent.PayloadValue
	}

	remoteIP := normalizeRemoteAddress(interaction.RemoteAddress)
	fromOwnIP := client.IsOwnIP(remoteIP)
	severity := correlator.EvaluateSeverity(interaction.Protocol, fromOwnIP, e.cfg.OwnIP.Action)
	if severity == "" {
		client.Forget(interaction.UniqueID)
		return
	}

	pingback := database.Pingback{
		UniqueID:         interaction.UniqueID,
		ScanTaskID:       entry.ScanTaskID,
		TargetURL:        entry.TargetURL,
		PayloadType:      entry.PayloadType,
		PayloadKey:       entry.PayloadKey,
		PayloadValue:     coalesce(entry.PayloadVal, interaction.FullId),
		CallbackProtocol: protocol,
		RemoteAddress:    remoteIP,
		ReverseDNS:       reverseLookup(remoteIP),
		AsnInfo:          mustJSON(interaction.AsnInfo),
		RawRequest:       interaction.RawRequest,
		SentAt:           entry.SentAt,
		ReceivedAt:       interaction.Timestamp.UTC(),
		DelaySeconds:     interaction.Timestamp.Sub(entry.SentAt).Seconds(),
		Severity:         severity,
		FromOwnIP:        fromOwnIP,
	}
	if err := e.db.Create(&pingback).Error; err != nil {
		return
	}
	e.maybeNotifyFinding(pingback)

	client.Forget(interaction.UniqueID)
	e.db.Model(&database.ScanTask{}).Where("id = ?", entry.ScanTaskID).UpdateColumn("pingback_count", gorm.Expr("pingback_count + 1"))
	e.broadcast(map[string]any{
		"type":    "pingback",
		"task_id": entry.ScanTaskID,
		"data":    pingback,
	})
}

func (e *Engine) loadPayloads(mode string) ([]payload.Payload, error) {
	var rows []database.PayloadTemplate
	if err := e.db.Order("position asc").Find(&rows).Error; err != nil {
		return nil, err
	}

	items := make([]payload.Payload, 0, len(rows))
	for _, row := range rows {
		item := payload.Payload{
			ID:      row.ID,
			Active:  row.Active,
			Type:    payload.Type(row.Type),
			Key:     row.Key,
			Value:   row.Value,
			Group:   row.Group,
			Comment: row.Comment,
		}
		items = append(items, item)
	}
	return selectPayloadsForMode(items, mode), nil
}

func (e *Engine) pingbackExists(uniqueID string, protocol string) (bool, error) {
	var count int64
	if err := e.db.Model(&database.Pingback{}).Where("unique_id = ? AND callback_protocol = ?", uniqueID, protocol).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (e *Engine) incrementRequestCount(taskID string, total int) {
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).UpdateColumn("request_sent", gorm.Expr("request_sent + 1"))
	e.broadcastProgress(taskID, 0, total)
}

func (e *Engine) setTaskActivity(taskID string, batchIndex int, target string, stage string, total int) {
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
		"current_batch":  batchIndex,
		"current_target": target,
		"current_stage":  stage,
	})
	e.broadcastProgress(taskID, 0, total)
}

func (e *Engine) markTargetCompleted(taskID string, batchIndex int, total int) {
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
		"current_batch":     batchIndex,
		"completed_targets": gorm.Expr("completed_targets + 1"),
	})
	e.broadcastProgress(taskID, 0, total)
}

func (e *Engine) finishTask(taskID string, status string) {
	now := time.Now().UTC()
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
		"status":         status,
		"completed_at":   now,
		"current_target": "",
		"current_stage":  status,
	})
	e.broadcast(map[string]any{
		"type":    "task_status",
		"task_id": taskID,
		"scan_id": taskID,
		"status":  status,
	})
}

func (e *Engine) failTask(taskID string, err error, detail string) {
	lastError := ""
	if err != nil {
		lastError = err.Error()
	}

	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
		"status":         "failed",
		"last_error":     lastError,
		"completed_at":   time.Now().UTC(),
		"current_target": "",
		"current_stage":  "failed",
	})
	e.broadcast(map[string]any{
		"type":    "task_status",
		"task_id": taskID,
		"scan_id": taskID,
		"status":  "failed",
		"error":   lastError,
	})
	e.maybeNotifyTaskFailure(taskID, err, detail)
}

func (e *Engine) maybeNotifyTaskFailure(taskID string, err error, detail string) {
	cfg := e.cfg.Notification
	if !cfg.Enabled || strings.TrimSpace(cfg.FeishuWebhook) == "" {
		return
	}

	var task database.ScanTask
	if dbErr := e.db.First(&task, "id = ?", taskID).Error; dbErr != nil {
		log.Printf("load failed task for notification failed task=%s err=%v", taskID, dbErr)
		return
	}

	configPreview := strings.TrimSpace(task.Config)
	if strings.TrimSpace(detail) != "" {
		if configPreview != "" {
			configPreview += "\n\n"
		}
		configPreview += strings.TrimSpace(detail)
	}

	alert := notify.BuildScanErrorAlert(
		task.ID,
		task.Mode,
		task.TargetCount,
		task.RequestSent,
		err,
		cfg.FrontendBaseURL,
		configPreview,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	response, notifyErr := notify.SendFeishuScanErrorCard(ctx, cfg.FeishuWebhook, alert)
	if notifyErr != nil {
		log.Printf("send scan failure notification failed task=%s err=%v response=%s", taskID, notifyErr, response)
	}
}

func (e *Engine) clearTask(taskID string) {
	e.mu.Lock()
	delete(e.running, taskID)
	e.mu.Unlock()
}

func (e *Engine) broadcast(message any) {
	if e.broadcaster != nil {
		e.broadcaster.Broadcast(message)
	}
}

func (e *Engine) broadcastLog(taskID string, level string, message string) {
	log.Printf("[%s] %s: %s", taskID[:8], level, message)
	e.broadcast(map[string]any{
		"type":    "scan_log",
		"task_id": taskID,
		"scan_id": taskID,
		"level":   level,
		"message": message,
		"time":    time.Now().UTC(),
	})
}

func (e *Engine) broadcastProgress(taskID string, sent int, total int) {
	var task database.ScanTask
	if err := e.db.Select("request_sent", "target_count", "estimated_requests", "batch_size", "batch_count", "current_batch", "completed_targets", "current_target", "current_stage", "status").First(&task, "id = ?", taskID).Error; err != nil {
		return
	}
	if sent <= 0 {
		sent = task.RequestSent
	}
	e.broadcast(map[string]any{
		"type":               "scan_progress",
		"task_id":            taskID,
		"scan_id":            taskID,
		"sent":               sent,
		"total":              total,
		"status":             task.Status,
		"target_count":       task.TargetCount,
		"estimated_requests": task.EstimatedRequests,
		"batch_size":         task.BatchSize,
		"batch_count":        task.BatchCount,
		"current_batch":      task.CurrentBatch,
		"completed_targets":  task.CompletedTargets,
		"current_target":     task.CurrentTarget,
		"current_stage":      task.CurrentStage,
	})
}

func (r *StartScanRequest) applyDefaults(cfg appconfig.Config) {
	r.Mode = normalizeScanMode(r.Mode)
	if r.Mode == "" {
		r.Mode = scanModeQuick
	}
	if r.Concurrency <= 0 {
		r.Concurrency = cfg.Scanner.DefaultConcurrency
	}
	if r.BatchSize <= 0 {
		r.BatchSize = cfg.Scanner.DefaultBatchSize
	}
	if r.RateLimit < -1 {
		r.RateLimit = -1
	}
	if r.RateLimit == 0 {
		r.RateLimit = cfg.Scanner.DefaultRateLimit
	}
	if r.CallbackTimeoutMinutes <= 0 {
		r.CallbackTimeoutMinutes = cfg.Scanner.DefaultTimeoutMinute
	}
	if r.InteractshServer == "" {
		r.InteractshServer = cfg.Interactsh.ServerURL
	}
	if r.InteractshToken == "" {
		r.InteractshToken = cfg.Interactsh.Token
	}
	if r.DefaultOrigin == "" {
		r.DefaultOrigin = cfg.Scanner.DefaultOrigin
	}
	if r.DefaultReferer == "" {
		r.DefaultReferer = cfg.Scanner.DefaultReferer
	}
	if r.CustomHeaders == nil {
		r.CustomHeaders = map[string]string{}
	}
}

func normalizeScanMode(mode string) string {
	return strings.ToLower(strings.TrimSpace(mode))
}

func isSupportedScanMode(mode string) bool {
	switch normalizeScanMode(mode) {
	case scanModeQuick, scanModeFull:
		return true
	default:
		return false
	}
}

func selectPayloadsForMode(items []payload.Payload, mode string) []payload.Payload {
	selected := make([]payload.Payload, 0, len(items))
	switch normalizeScanMode(mode) {
	case scanModeQuick:
		for _, item := range items {
			if !item.Active {
				continue
			}
			if item.Group == "standard" && item.Type == payload.TypeHeader {
				selected = append(selected, item)
				continue
			}
			if item.Group == "cracking_the_lens" && item.Type == payload.TypeRaw && isQuickRawPayload(item.Key) {
				selected = append(selected, item)
			}
		}
	case scanModeFull:
		for _, item := range items {
			if item.Active {
				selected = append(selected, item)
			}
		}
	}
	return selected
}

func isQuickRawPayload(key string) bool {
	_, ok := quickRawPayloadKeys[strings.ToLower(strings.TrimSpace(key))]
	return ok
}

func canResolvePayload(item payload.Payload, opts payload.ResolveOptions) bool {
	if strings.Contains(item.Value, "%o") && opts.DefaultOrigin == "" {
		return false
	}
	if strings.Contains(item.Value, "%r") && opts.DefaultReferer == "" {
		return false
	}
	return true
}

func filterPayloadsByType(items []payload.Payload, kinds ...payload.Type) []payload.Payload {
	allowed := make(map[payload.Type]struct{}, len(kinds))
	for _, kind := range kinds {
		allowed[kind] = struct{}{}
	}

	var filtered []payload.Payload
	for _, item := range items {
		if _, ok := allowed[item.Type]; ok {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func splitHostPayloads(items []payload.Payload) ([]payload.Payload, []payload.Payload) {
	standard := make([]payload.Payload, 0, len(items))
	host := make([]payload.Payload, 0, len(items))
	for _, item := range items {
		if item.Type == payload.TypeHeader && strings.EqualFold(item.Key, "Host") {
			host = append(host, item)
			continue
		}
		standard = append(standard, item)
	}
	return standard, host
}

func filterTargets(targets []string, scope ScopeFilter) []string {
	var filtered []string
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		parsed, err := url.Parse(target)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if !matchesScope(host, scope.Include, true) {
			continue
		}
		if matchesScope(host, scope.Exclude, false) {
			continue
		}
		filtered = append(filtered, target)
	}
	return filtered
}

func matchesScope(host string, patterns []string, emptyDefault bool) bool {
	if len(patterns) == 0 {
		return emptyDefault
	}
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if ok, _ := filepath.Match(pattern, host); ok {
			return true
		}
		if host == pattern {
			return true
		}
	}
	return false
}

func buildAltTargets(target string, ports []int) []string {
	if len(ports) == 0 {
		return nil
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil
	}

	var results []string
	for _, port := range ports {
		if port <= 0 {
			continue
		}
		cloned := *parsed
		cloned.Host = net.JoinHostPort(parsed.Hostname(), fmt.Sprintf("%d", port))
		results = append(results, cloned.String())
	}
	return results
}

func batchCount(totalTargets int, batchSize int) int {
	if totalTargets <= 0 {
		return 0
	}
	if batchSize <= 0 {
		batchSize = totalTargets
	}
	count := totalTargets / batchSize
	if totalTargets%batchSize != 0 {
		count++
	}
	return count
}

func chunkTargets(targets []string, batchSize int) [][]string {
	if len(targets) == 0 {
		return nil
	}
	if batchSize <= 0 || batchSize >= len(targets) {
		return [][]string{append([]string(nil), targets...)}
	}

	chunks := make([][]string, 0, batchCount(len(targets), batchSize))
	for start := 0; start < len(targets); start += batchSize {
		end := start + batchSize
		if end > len(targets) {
			end = len(targets)
		}
		chunks = append(chunks, append([]string(nil), targets[start:end]...))
	}
	return chunks
}

func estimateTotalRequests(req StartScanRequest, items []payload.Payload) int {
	if len(req.Targets) == 0 || len(items) == 0 {
		return 0
	}

	standardCount := 0
	hostCount := 0
	rawCount := 0
	for _, item := range items {
		switch item.Type {
		case payload.TypeHeader, payload.TypeParam:
			if item.Type == payload.TypeHeader && strings.EqualFold(item.Key, "Host") {
				hostCount = 1
				continue
			}
			standardCount = 1
		case payload.TypeRaw:
			if item.Key != "alt-ports" {
				rawCount++
			}
		}
	}

	perTarget := standardCount + hostCount + rawCount
	if len(req.AltPorts) > 0 {
		for _, port := range req.AltPorts {
			if port > 0 {
				perTarget += standardCount + hostCount
			}
		}
	}
	return len(req.Targets) * perTarget
}

func firstLabel(value string) string {
	parts := strings.Split(value, ".")
	if len(parts) == 0 {
		return value
	}
	return parts[0]
}

func normalizeRemoteAddress(value string) string {
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		return host
	}
	return value
}

func reverseLookup(ip string) string {
	if ip == "" {
		return ""
	}
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func mustJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(data)
}

func coalesce(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
