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
	"strings"
	"sync"
	"time"

	appconfig "hidden-attack-surface-scanner/internal/config"
	"hidden-attack-surface-scanner/internal/database"
	"hidden-attack-surface-scanner/pkg/correlator"
	"hidden-attack-surface-scanner/pkg/oob"
	"hidden-attack-surface-scanner/pkg/payload"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

type Broadcaster interface {
	Broadcast(any)
}

type StartScanRequest struct {
	Targets                []string          `json:"targets"`
	Mode                   string            `json:"mode"`
	Concurrency            int               `json:"concurrency"`
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
		Status:      "pending",
		Mode:        strings.ToLower(req.Mode),
		Config:      string(configJSON),
		TargetCount: len(req.Targets),
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
	defer e.clearTask(taskID)

	now := time.Now().UTC()
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
		"status":     "running",
		"started_at": now,
		"last_error": "",
	})
	e.broadcast(map[string]any{
		"type":    "task_status",
		"task_id": taskID,
		"scan_id": taskID,
		"status":  "running",
	})

	client, err := oob.New(req.InteractshServer, req.InteractshToken)
	if err != nil {
		e.failTask(taskID, err)
		return
	}
	defer client.Stop()

	e.broadcastLog(taskID, "info", "Initializing HTTP client...")
	httpClient, err := NewHTTPClient(req.Proxy, 15*time.Second)
	if err != nil {
		e.failTask(taskID, err)
		return
	}

	e.broadcastLog(taskID, "info", "Starting OOB interaction polling (interval=5s)...")
	if err := client.StartPolling(5*time.Second, func(interaction *server.Interaction, entry oob.CorrelationEntry, ok bool) {
		e.handleInteraction(taskID, client, interaction, entry, ok)
	}); err != nil {
		e.failTask(taskID, err)
		return
	}

	e.broadcastLog(taskID, "info", "Detecting own IP via interactsh...")
	if err := client.DetectOwnIP(httpClient); err != nil {
		e.broadcastLog(taskID, "warn", fmt.Sprintf("Own-IP detection failed (callbacks from own IP will not be filtered): %v", err))
	}

	e.broadcastLog(taskID, "info", fmt.Sprintf("Loading payloads for mode=%s...", req.Mode))
	items, err := e.loadPayloads(req.Mode)
	if err != nil {
		e.failTask(taskID, err)
		return
	}
	e.broadcastLog(taskID, "info", fmt.Sprintf("Loaded %d payloads, dispatching to %d targets (concurrency=%d, rate_limit=%d)...",
		len(items), len(req.Targets), req.Concurrency, req.RateLimit))
	totalRequests := estimateTotalRequests(req, items)
	e.broadcastProgress(taskID, 0, totalRequests)

	if err := e.dispatch(ctx, taskID, req, client, httpClient, items, totalRequests); err != nil && !errors.Is(err, context.Canceled) {
		e.failTask(taskID, err)
		return
	}

	if errors.Is(ctx.Err(), context.Canceled) {
		e.finishTask(taskID, "stopped")
		return
	}

	e.broadcastLog(taskID, "info", fmt.Sprintf("All requests dispatched. Waiting for OOB callbacks (timeout=%dm)...", req.CallbackTimeoutMinutes))
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{"status": "waiting_callback"})
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
	items []payload.Payload,
	totalRequests int,
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
				if err := limiter.Wait(ctx); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
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
	rawPayloads := filterPayloadsByType(items, payload.TypeRaw)

enqueueLoop:
	for _, target := range req.Targets {
		target := target
		if len(standardPayloads) > 0 {
			select {
			case jobs <- func() error {
				return e.sendStandardTarget(ctx, taskID, req, client, httpClient, target, standardPayloads, totalRequests)
			}:
			case <-ctx.Done():
				break enqueueLoop
			}
		}

		for _, rawPayload := range rawPayloads {
			if rawPayload.Key == "alt-ports" {
				continue
			}
			rawPayload := rawPayload
			select {
			case jobs <- func() error { return e.sendRawTarget(ctx, taskID, req, client, target, rawPayload, totalRequests) }:
			case <-ctx.Done():
				break enqueueLoop
			}
		}

		for _, altTarget := range buildAltTargets(target, req.AltPorts) {
			altTarget := altTarget
			if len(standardPayloads) == 0 {
				continue
			}
			select {
			case jobs <- func() error {
				return e.sendStandardTarget(ctx, taskID, req, client, httpClient, altTarget, standardPayloads, totalRequests)
			}:
			case <-ctx.Done():
				break enqueueLoop
			}
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
	e.broadcastLog(taskID, "debug", fmt.Sprintf("Scanning target: %s (%d payloads)", target, len(items)))
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
	if err := e.db.Create(&sentRows).Error; err != nil {
		return err
	}

	statusCode, err := SendStandardRequest(ctx, httpClient, target, resolved, req.CustomHeaders)
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
	sent := database.SentPayload{
		UniqueID:     uniqueID,
		ScanTaskID:   taskID,
		TargetURL:    target,
		PayloadType:  string(item.Type),
		PayloadKey:   item.Key,
		PayloadValue: string(rawRequest.RawBytes),
		SentAt:       entry.SentAt,
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

	if exists, _ := e.pingbackExists(interaction.UniqueID); exists {
		return
	}

	if ok && entry.OwnIPProbe {
		client.RememberOwnIP(normalizeRemoteAddress(interaction.RemoteAddress))
		client.Forget(interaction.UniqueID)
		return
	}

	if !ok {
		var sent database.SentPayload
		if err := e.db.First(&sent, "unique_id = ?", interaction.UniqueID).Error; err != nil {
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
		if err := e.db.First(&sent, "unique_id = ?", interaction.UniqueID).Error; err != nil {
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
		CallbackProtocol: strings.ToLower(interaction.Protocol),
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
		switch strings.ToLower(mode) {
		case "quick":
			if item.Group == "standard" && item.Active && item.Type == payload.TypeHeader {
				items = append(items, item)
			}
		case "full":
			if item.Group == "standard" && item.Active {
				items = append(items, item)
			}
		case "cracking":
			if (item.Group == "standard" || item.Group == "cracking_the_lens") && item.Active {
				items = append(items, item)
			}
		default:
			if item.Active {
				items = append(items, item)
			}
		}
	}
	return items, nil
}

func (e *Engine) pingbackExists(uniqueID string) (bool, error) {
	var count int64
	if err := e.db.Model(&database.Pingback{}).Where("unique_id = ?", uniqueID).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (e *Engine) incrementRequestCount(taskID string, total int) {
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).UpdateColumn("request_sent", gorm.Expr("request_sent + 1"))

	var task database.ScanTask
	if err := e.db.Select("request_sent").First(&task, "id = ?", taskID).Error; err != nil {
		return
	}
	e.broadcastProgress(taskID, task.RequestSent, total)
}

func (e *Engine) finishTask(taskID string, status string) {
	now := time.Now().UTC()
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
		"status":       status,
		"completed_at": now,
	})
	e.broadcast(map[string]any{
		"type":    "task_status",
		"task_id": taskID,
		"scan_id": taskID,
		"status":  status,
	})
}

func (e *Engine) failTask(taskID string, err error) {
	e.db.Model(&database.ScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
		"status":       "failed",
		"last_error":   err.Error(),
		"completed_at": time.Now().UTC(),
	})
	e.broadcast(map[string]any{
		"type":    "task_status",
		"task_id": taskID,
		"scan_id": taskID,
		"status":  "failed",
		"error":   err.Error(),
	})
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
	e.broadcast(map[string]any{
		"type":    "scan_progress",
		"task_id": taskID,
		"scan_id": taskID,
		"sent":    sent,
		"total":   total,
	})
}

func (r *StartScanRequest) applyDefaults(cfg appconfig.Config) {
	if r.Mode == "" {
		r.Mode = "quick"
	}
	if r.Concurrency <= 0 {
		r.Concurrency = cfg.Scanner.DefaultConcurrency
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

func estimateTotalRequests(req StartScanRequest, items []payload.Payload) int {
	if len(req.Targets) == 0 || len(items) == 0 {
		return 0
	}

	standardCount := 0
	rawCount := 0
	for _, item := range items {
		switch item.Type {
		case payload.TypeHeader, payload.TypeParam:
			standardCount = 1
		case payload.TypeRaw:
			if item.Key != "alt-ports" {
				rawCount++
			}
		}
	}

	perTarget := standardCount + rawCount
	if standardCount > 0 && len(req.AltPorts) > 0 {
		for _, port := range req.AltPorts {
			if port > 0 {
				perTarget++
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
