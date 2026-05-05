package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	appconfig "github.com/blackfight1/everywhere/internal/config"
	"github.com/blackfight1/everywhere/internal/database"
	"github.com/blackfight1/everywhere/pkg/correlator"
	"github.com/blackfight1/everywhere/pkg/notify"
	"github.com/blackfight1/everywhere/pkg/oob"
	"github.com/blackfight1/everywhere/pkg/payload"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

type Broadcaster interface {
	Broadcast(any)
}

const (
	scanModeRaw = "raw"
)

type StartScanRequest struct {
	Targets                []string    `json:"targets"`
	TargetSetID            string      `json:"target_set_id"`
	Mode                   string      `json:"mode"`
	Concurrency            int         `json:"concurrency"`
	BatchSize              int         `json:"batch_size"`
	RateLimit              int         `json:"rate_limit"`
	CallbackTimeoutMinutes int         `json:"callback_timeout_minutes"`
	Proxy                  string      `json:"proxy"`
	InteractshServer       string      `json:"interactsh_server"`
	InteractshToken        string      `json:"interactsh_token"`
	ScopeFilter            ScopeFilter `json:"scope_filter"`
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

	var targetSet database.TargetSet
	targetCount := 0
	targetSetName := ""
	if strings.TrimSpace(req.TargetSetID) != "" {
		if err := e.db.First(&targetSet, "id = ?", strings.TrimSpace(req.TargetSetID)).Error; err != nil {
			return nil, fmt.Errorf("target set not found: %s", req.TargetSetID)
		}
		if targetSet.Status != "ready" {
			return nil, fmt.Errorf("target set is not ready: %s", targetSet.Status)
		}
		targetCount = targetSet.DedupedCount
		targetSetName = targetSet.Name
		req.TargetSetID = targetSet.ID
	} else {
		if len(req.Targets) == 0 {
			return nil, errors.New("targets cannot be empty")
		}

		filteredTargets := filterTargets(req.Targets, req.ScopeFilter)
		if len(filteredTargets) == 0 {
			return nil, errors.New("no targets remain after scope filtering")
		}
		req.Targets = filteredTargets
		targetCount = len(req.Targets)
	}
	if targetCount == 0 {
		return nil, errors.New("no targets remain after preprocessing")
	}

	configJSON, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	task := &database.ScanTask{
		Status:        "pending",
		Mode:          strings.ToLower(req.Mode),
		TargetSetID:   req.TargetSetID,
		TargetSetName: targetSetName,
		Config:        string(configJSON),
		TargetCount:   targetCount,
		BatchSize:     req.BatchSize,
		BatchCount:    batchCount(targetCount, req.BatchSize),
		CurrentStage:  "queued",
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

	var scanTask database.ScanTask
	if err := e.db.Select("id", "target_count", "batch_count", "batch_size").First(&scanTask, "id = ?", taskID).Error; err != nil {
		e.failTask(taskID, err, "")
		return
	}
	e.maybeNotifyScanStarted(scanTask)

	client, err := oob.New(req.InteractshServer, req.InteractshToken)
	if err != nil {
		e.failTask(taskID, err, "")
		return
	}
	defer client.Stop()

	if seeded := client.RememberLocalInterfaceIPs(); seeded > 0 {
		e.broadcastLog(taskID, "info", fmt.Sprintf("Seeded %d local interface IP(s) for own-IP filtering.", seeded))
	}

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
		len(items), scanTask.TargetCount, req.Concurrency, req.RateLimit))
	totalRequests := estimateTotalRequests(req, items, scanTask.TargetCount)
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Update("estimated_requests", totalRequests)
	e.broadcastProgress(taskID, 0, totalRequests)

	if strings.TrimSpace(req.TargetSetID) == "" {
		batches := chunkTargets(req.Targets, req.BatchSize)
		e.broadcastLog(taskID, "info", fmt.Sprintf("Split %d targets into %d batch(es) with batch_size=%d.", len(req.Targets), len(batches), req.BatchSize))
		for idx, targets := range batches {
			batchIndex := idx + 1
			e.broadcastLog(taskID, "info", fmt.Sprintf("Batch %d/%d started (%d targets).", batchIndex, len(batches), len(targets)))
			e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
				"current_batch": batchIndex,
				"current_stage": "dispatching",
			})
			e.broadcastProgress(taskID, 0, totalRequests)

			if err := e.dispatch(ctx, taskID, req, client, targets, items, totalRequests, batchIndex, len(batches)); err != nil && !errors.Is(err, context.Canceled) {
				e.failTask(taskID, err, "")
				return
			}
			if errors.Is(ctx.Err(), context.Canceled) {
				break
			}
			e.broadcastLog(taskID, "info", fmt.Sprintf("Batch %d/%d dispatched.", batchIndex, len(batches)))
		}
	} else {
		e.broadcastLog(taskID, "info", fmt.Sprintf("Reading targets from set %s in batch_size=%d.", req.TargetSetID, req.BatchSize))
		lastPosition := -1
		for batchIndex := 1; ; batchIndex++ {
			targets, nextPosition, err := e.loadTargetSetBatch(req.TargetSetID, lastPosition, req.BatchSize)
			if err != nil {
				e.failTask(taskID, err, "")
				return
			}
			if len(targets) == 0 {
				break
			}
			lastPosition = nextPosition
			e.broadcastLog(taskID, "info", fmt.Sprintf("Batch %d/%d started (%d targets).", batchIndex, scanTask.BatchCount, len(targets)))
			e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
				"current_batch": batchIndex,
				"current_stage": "dispatching",
			})
			e.broadcastProgress(taskID, 0, totalRequests)

			if err := e.dispatch(ctx, taskID, req, client, targets, items, totalRequests, batchIndex, scanTask.BatchCount); err != nil && !errors.Is(err, context.Canceled) {
				e.failTask(taskID, err, "")
				return
			}
			if errors.Is(ctx.Err(), context.Canceled) {
				break
			}
			e.broadcastLog(taskID, "info", fmt.Sprintf("Batch %d/%d dispatched.", batchIndex, scanTask.BatchCount))
			if len(targets) < req.BatchSize {
				break
			}
		}
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
	e.maybeNotifyDispatchFinished(taskID)

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

enqueueLoop:
	for idx, target := range targets {
		target := target
		targetOrdinal := idx + 1
		select {
		case jobs <- func() error {
			return e.scanTarget(ctx, taskID, client, limiter, target, items, totalRequests, batchIndex, batchTotal, targetOrdinal, len(targets))
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
	client *oob.Client,
	limiter *rate.Limiter,
	target string,
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

	for _, rawPayload := range rawPayloads {
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
		e.setTaskActivity(taskID, batchIndex, target, "raw-"+rawPayload.Key, totalRequests)
		e.broadcastLog(taskID, "debug", fmt.Sprintf("Batch %d/%d target %d/%d raw %s dispatched: %s", batchIndex, batchTotal, targetOrdinal, batchTargetCount, rawPayload.Key, target))
		if rawPayload.Key == proxyLocalSSHPayloadKey {
			if _, err := e.sendProxyUnsafeTarget(ctx, taskID, target, totalRequests); err != nil {
				return err
			}
			continue
		}
		if err := e.sendRawTarget(ctx, taskID, client, target, rawPayload, totalRequests); err != nil {
			return err
		}
	}

	e.markTargetCompleted(taskID, batchIndex, totalRequests)
	e.broadcastLog(taskID, "debug", fmt.Sprintf("Batch %d/%d target %d/%d completed: %s", batchIndex, batchTotal, targetOrdinal, batchTargetCount, target))
	return nil
}

func (e *Engine) sendRawTarget(
	ctx context.Context,
	taskID string,
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
	e.maybeNotifyScanFinished(taskID, status)
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
		"",
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
		r.Mode = scanModeRaw
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
}

func normalizeScanMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return scanModeRaw
	}
	return scanModeRaw
}

func selectPayloadsForMode(items []payload.Payload, _ string) []payload.Payload {
	selected := make([]payload.Payload, 0, len(items))
	for _, item := range items {
		if item.Active && item.Type == payload.TypeRaw {
			selected = append(selected, item)
		}
	}
	return selected
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

func (e *Engine) loadTargetSetBatch(targetSetID string, lastPosition int, batchSize int) ([]string, int, error) {
	if batchSize <= 0 {
		batchSize = 1500
	}

	var rows []database.TargetRecord
	query := e.db.Select("url", "position").
		Where("target_set_id = ? AND position > ?", targetSetID, lastPosition).
		Order("position asc").
		Limit(batchSize)
	if err := query.Find(&rows).Error; err != nil {
		return nil, lastPosition, err
	}

	targets := make([]string, 0, len(rows))
	nextPosition := lastPosition
	for _, row := range rows {
		targets = append(targets, row.URL)
		nextPosition = row.Position
	}
	return targets, nextPosition, nil
}

func estimateTotalRequests(_ StartScanRequest, items []payload.Payload, targetCount int) int {
	if targetCount == 0 || len(items) == 0 {
		return 0
	}

	rawCount := 0
	for _, item := range items {
		if item.Type == payload.TypeRaw {
			if item.Key == proxyLocalSSHPayloadKey {
				rawCount += len(proxyUnsafeVariants())
				continue
			}
			rawCount++
		}
	}
	return targetCount * rawCount
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
