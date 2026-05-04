package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	appconfig "hidden-attack-surface-scanner/internal/config"
	"hidden-attack-surface-scanner/internal/database"
	"hidden-attack-surface-scanner/pkg/payload"
	"hidden-attack-surface-scanner/pkg/scanner"

	"gorm.io/gorm"
)

type cliBroadcaster struct {
	mu          sync.Mutex
	taskStatus  map[string]string
	lastFinding map[string]struct{}
}

func newCLIBroadcaster() *cliBroadcaster {
	return &cliBroadcaster{
		taskStatus:  make(map[string]string),
		lastFinding: make(map[string]struct{}),
	}
}

func (b *cliBroadcaster) Broadcast(message any) {
	event, ok := message.(map[string]any)
	if !ok {
		return
	}

	eventType := stringify(event["type"])
	switch eventType {
	case "task_status":
		taskID := stringify(event["task_id"])
		status := stringify(event["status"])
		b.mu.Lock()
		b.taskStatus[taskID] = status
		b.mu.Unlock()
		log.Printf("[task %s] status=%s", shortID(taskID), status)
	case "scan_log":
		taskID := stringify(event["task_id"])
		level := strings.ToUpper(stringify(event["level"]))
		message := stringify(event["message"])
		log.Printf("[task %s] [%s] %s", shortID(taskID), level, message)
	case "scan_progress":
		taskID := stringify(event["task_id"])
		sent := intify(event["sent"])
		total := intify(event["total"])
		currentBatch := intify(event["current_batch"])
		batchCount := intify(event["batch_count"])
		completedTargets := intify(event["completed_targets"])
		targetCount := intify(event["target_count"])
		stage := stringify(event["current_stage"])
		currentTarget := stringify(event["current_target"])
		if currentTarget != "" {
			log.Printf("[task %s] progress sent=%d/%d targets=%d/%d batch=%d/%d stage=%s current=%s",
				shortID(taskID), sent, total, completedTargets, targetCount, currentBatch, batchCount, stage, currentTarget)
			return
		}
		log.Printf("[task %s] progress sent=%d/%d targets=%d/%d batch=%d/%d stage=%s",
			shortID(taskID), sent, total, completedTargets, targetCount, currentBatch, batchCount, stage)
	case "pingback":
		taskID := stringify(event["task_id"])
		payload, _ := event["data"].(map[string]any)
		protocol := stringify(payload["callback_protocol"])
		target := stringify(payload["target_url"])
		payloadKey := stringify(payload["payload_key"])
		remote := stringify(payload["remote_address"])
		severity := stringify(payload["severity"])
		unique := fmt.Sprintf("%s|%s|%s|%s", taskID, protocol, target, payloadKey)
		b.mu.Lock()
		if _, exists := b.lastFinding[unique]; exists {
			b.mu.Unlock()
			return
		}
		b.lastFinding[unique] = struct{}{}
		b.mu.Unlock()
		log.Printf("[task %s] finding protocol=%s severity=%s payload=%s target=%s remote=%s",
			shortID(taskID), protocol, severity, payloadKey, target, remote)
	}
}

func main() {
	var (
		configPath   = flag.String("config", "configs/config.yaml", "path to config file")
		payloadPath  = flag.String("payloads", "configs/injections.yaml", "path to payload config")
		targetFile   = flag.String("targets-file", "", "path to newline-delimited target file")
		targetSingle = flag.String("target", "", "single target URL")
		mode         = flag.String("mode", "quick", "scan mode: quick or full")
		concurrency  = flag.Int("concurrency", 0, "worker concurrency")
		batchSize    = flag.Int("batch-size", 0, "targets per batch")
		rateLimit    = flag.Int("rate-limit", 0, "request rate limit per second, -1 for unlimited")
		timeoutMins  = flag.Int("callback-timeout", 0, "callback wait timeout in minutes")
		proxy        = flag.String("proxy", "", "HTTP/HTTPS/SOCKS5 proxy")
		origin       = flag.String("default-origin", "", "default origin placeholder")
		referer      = flag.String("default-referer", "", "default referer placeholder")
		interactsh   = flag.String("interactsh-server", "", "custom Interactsh server")
		interactTok  = flag.String("interactsh-token", "", "custom Interactsh token")
		writeJSON    = flag.Bool("json-summary", false, "print final JSON summary")
	)
	flag.Parse()

	if err := ensureConfigFile(*configPath); err != nil {
		log.Fatalf("prepare config: %v", err)
	}

	cfg, err := appconfig.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db, err := database.Open(cfg)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}

	payloads, err := payload.LoadFromYAML(*payloadPath)
	if err != nil {
		log.Fatalf("load payloads: %v", err)
	}
	if err := database.SeedPayloads(db, payloads); err != nil {
		log.Fatalf("seed payloads: %v", err)
	}

	targets, err := loadTargets(*targetSingle, *targetFile)
	if err != nil {
		log.Fatalf("load targets: %v", err)
	}
	if len(targets) == 0 {
		log.Fatal("no targets provided: use -target or -targets-file")
	}

	broadcaster := newCLIBroadcaster()
	engine := scanner.NewEngine(db, cfg, broadcaster)
	req := scanner.StartScanRequest{
		Targets:                targets,
		Mode:                   *mode,
		Concurrency:            *concurrency,
		BatchSize:              *batchSize,
		RateLimit:              *rateLimit,
		CallbackTimeoutMinutes: *timeoutMins,
		Proxy:                  strings.TrimSpace(*proxy),
		InteractshServer:       strings.TrimSpace(*interactsh),
		InteractshToken:        strings.TrimSpace(*interactTok),
		DefaultOrigin:          strings.TrimSpace(*origin),
		DefaultReferer:         strings.TrimSpace(*referer),
		CustomHeaders:          map[string]string{},
	}

	task, err := engine.StartScan(req)
	if err != nil {
		log.Fatalf("start scan: %v", err)
	}
	log.Printf("started task=%s mode=%s targets=%d batch_size=%d", task.ID, task.Mode, task.TargetCount, task.BatchSize)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		log.Printf("signal received, stopping task=%s", task.ID)
		_ = engine.StopScan(task.ID)
	}()

	finalTask, results, err := waitForTaskCompletion(ctx, db, task.ID)
	if err != nil {
		log.Fatalf("wait task: %v", err)
	}

	printSummary(finalTask, results, *writeJSON)
	switch strings.ToLower(strings.TrimSpace(finalTask.Status)) {
	case "completed", "waiting_callback", "stopped":
		return
	default:
		os.Exit(1)
	}
}

func ensureConfigFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return appconfig.Save(path, appconfig.Default())
}

func loadTargets(single string, filePath string) ([]string, error) {
	var targets []string
	if value := strings.TrimSpace(single); value != "" {
		targets = append(targets, value)
	}
	if strings.TrimSpace(filePath) == "" {
		return targets, nil
	}

	data, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		targets = append(targets, line)
	}
	return dedupeStrings(targets), nil
}

func waitForTaskCompletion(ctx context.Context, db *gorm.DB, taskID string) (database.ScanTask, []database.Pingback, error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		var task database.ScanTask
		if err := db.First(&task, "id = ?", taskID).Error; err != nil {
			return database.ScanTask{}, nil, err
		}

		switch strings.ToLower(strings.TrimSpace(task.Status)) {
		case "completed", "failed", "stopped":
			var results []database.Pingback
			if err := db.Where("scan_task_id = ?", taskID).Order("received_at desc").Find(&results).Error; err != nil {
				return task, nil, err
			}
			return task, results, nil
		}

		select {
		case <-ctx.Done():
			return task, nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func printSummary(task database.ScanTask, results []database.Pingback, asJSON bool) {
	if asJSON {
		summary := map[string]any{
			"task_id":             task.ID,
			"status":              task.Status,
			"mode":                task.Mode,
			"targets":             task.TargetCount,
			"estimated_requests":  task.EstimatedRequests,
			"requests_sent":       task.RequestSent,
			"pingback_count":      task.PingbackCount,
			"batch_count":         task.BatchCount,
			"completed_targets":   task.CompletedTargets,
			"current_stage":       task.CurrentStage,
			"started_at":          task.StartedAt,
			"completed_at":        task.CompletedAt,
			"last_error":          task.LastError,
			"findings_by_payload": countByPayload(results),
			"findings_by_proto":   countByProtocol(results),
		}
		data, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println()
	fmt.Println("Scan Summary")
	fmt.Printf("Task ID: %s\n", task.ID)
	fmt.Printf("Status: %s\n", task.Status)
	fmt.Printf("Mode: %s\n", task.Mode)
	fmt.Printf("Targets: %d\n", task.TargetCount)
	fmt.Printf("Requests sent: %d / %d\n", task.RequestSent, task.EstimatedRequests)
	fmt.Printf("Pingbacks: %d\n", task.PingbackCount)
	if strings.TrimSpace(task.LastError) != "" {
		fmt.Printf("Last error: %s\n", task.LastError)
	}
	fmt.Println()
	fmt.Println("Findings By Payload")
	for key, count := range countByPayload(results) {
		fmt.Printf("- %s: %d\n", key, count)
	}
	fmt.Println()
	fmt.Println("Findings By Protocol")
	for key, count := range countByProtocol(results) {
		fmt.Printf("- %s: %d\n", key, count)
	}
}

func countByPayload(results []database.Pingback) map[string]int {
	counts := make(map[string]int)
	for _, item := range results {
		counts[item.PayloadKey]++
	}
	return counts
}

func countByProtocol(results []database.Pingback) map[string]int {
	counts := make(map[string]int)
	for _, item := range results {
		counts[item.CallbackProtocol]++
	}
	return counts
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func stringify(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return fmt.Sprintf("%v", value)
	}
}

func intify(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
}

func shortID(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[:8]
}
