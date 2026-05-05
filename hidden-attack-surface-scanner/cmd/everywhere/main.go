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
	"hidden-attack-surface-scanner/pkg/notify"
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
	case "response_finding":
		taskID := stringify(event["task_id"])
		payload, _ := event["data"].(map[string]any)
		target := stringify(payload["target_url"])
		payloadKey := stringify(payload["payload_key"])
		method := stringify(payload["request_method"])
		upstream := stringify(payload["upstream"])
		confidence := stringify(payload["confidence"])
		unique := fmt.Sprintf("%s|response|%s|%s|%s", taskID, target, payloadKey, upstream)
		b.mu.Lock()
		if _, exists := b.lastFinding[unique]; exists {
			b.mu.Unlock()
			return
		}
		b.lastFinding[unique] = struct{}{}
		b.mu.Unlock()
		log.Printf("[task %s] response-finding confidence=%s payload=%s target=%s method=%s upstream=%s",
			shortID(taskID), confidence, payloadKey, target, method, upstream)
	}
}

type scanOptions struct {
	configPath  string
	payloadPath string
	targetFile  string
	target      string
	concurrency int
	batchSize   int
	rateLimit   int
	timeoutMins int
	proxy       string
	interactsh  string
	interactTok string
	writeJSON   bool
}

func main() {
	log.SetFlags(log.LstdFlags)

	command := "scan"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = strings.ToLower(strings.TrimSpace(args[0]))
		args = args[1:]
	}

	switch command {
	case "scan":
		runScan(args)
	case "notify-test":
		runNotifyTest(args)
	case "help", "-h", "--help":
		printRootHelp()
	default:
		log.Fatalf("unknown command: %s", command)
	}
}

func runScan(args []string) {
	opts := scanOptions{}
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	fs.StringVar(&opts.configPath, "config", "configs/config.yaml", "path to config file")
	fs.StringVar(&opts.payloadPath, "payloads", "configs/injections.yaml", "path to payload config")
	fs.StringVar(&opts.target, "target", "", "single target URL")
	fs.StringVar(&opts.targetFile, "targets-file", "", "path to newline-delimited target file")
	fs.IntVar(&opts.concurrency, "concurrency", 0, "worker concurrency")
	fs.IntVar(&opts.batchSize, "batch-size", 0, "targets per batch")
	fs.IntVar(&opts.rateLimit, "rate-limit", 0, "request rate limit per second, -1 for unlimited")
	fs.IntVar(&opts.timeoutMins, "callback-timeout", 0, "callback wait timeout in minutes")
	fs.StringVar(&opts.proxy, "proxy", "", "HTTP/HTTPS/SOCKS5 proxy")
	fs.StringVar(&opts.interactsh, "interactsh-server", "", "custom Interactsh server")
	fs.StringVar(&opts.interactTok, "interactsh-token", "", "custom Interactsh token")
	fs.BoolVar(&opts.writeJSON, "json-summary", false, "print final JSON summary")
	fs.Usage = func() {
		fmt.Println("Usage:")
		fmt.Println("  everywhere scan -target https://example.com")
		fmt.Println("  everywhere scan -targets-file targets.txt")
		fmt.Println()
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if err := ensureConfigFile(opts.configPath); err != nil {
		log.Fatalf("prepare config: %v", err)
	}

	cfg, err := appconfig.Load(opts.configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db, err := database.Open(cfg)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}

	payloads, err := payload.LoadFromYAML(opts.payloadPath)
	if err != nil {
		log.Fatalf("load payloads: %v", err)
	}
	if err := database.SyncPayloads(db, payloads); err != nil {
		log.Fatalf("sync payloads: %v", err)
	}

	targets, err := loadTargets(opts.target, opts.targetFile)
	if err != nil {
		log.Fatalf("load targets: %v", err)
	}
	if len(targets) == 0 {
		log.Fatal("no targets provided: use `everywhere scan -target ...` or `everywhere scan -targets-file ...`")
	}

	broadcaster := newCLIBroadcaster()
	engine := scanner.NewEngine(db, cfg, broadcaster)
	req := scanner.StartScanRequest{
		Targets:                targets,
		Mode:                   "raw",
		Concurrency:            opts.concurrency,
		BatchSize:              opts.batchSize,
		RateLimit:              opts.rateLimit,
		CallbackTimeoutMinutes: opts.timeoutMins,
		Proxy:                  strings.TrimSpace(opts.proxy),
		InteractshServer:       strings.TrimSpace(opts.interactsh),
		InteractshToken:        strings.TrimSpace(opts.interactTok),
	}

	task, err := engine.StartScan(req)
	if err != nil {
		log.Fatalf("start scan: %v", err)
	}
	log.Printf("started task=%s targets=%d batch_size=%d", task.ID, task.TargetCount, task.BatchSize)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		log.Printf("signal received, stopping task=%s", task.ID)
		_ = engine.StopScan(task.ID)
	}()

	finalTask, pingbacks, responseFindings, err := waitForTaskCompletion(ctx, db, task.ID)
	if err != nil {
		log.Fatalf("wait task: %v", err)
	}

	printSummary(finalTask, pingbacks, responseFindings, opts.writeJSON)
	switch strings.ToLower(strings.TrimSpace(finalTask.Status)) {
	case "completed", "waiting_callback", "stopped":
		return
	default:
		os.Exit(1)
	}
}

func printRootHelp() {
	fmt.Println("Everywhere CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  everywhere scan -target https://example.com")
	fmt.Println("  everywhere scan -targets-file targets.txt")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  scan    run the raw payload scanner")
	fmt.Println("  notify-test    send a test Feishu notification")
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

func runNotifyTest(args []string) {
	fs := flag.NewFlagSet("notify-test", flag.ExitOnError)
	configPath := fs.String("config", "configs/config.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	cfg, err := appconfig.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if !cfg.Notification.Enabled {
		log.Fatal("notification.enabled is false")
	}
	if strings.TrimSpace(cfg.Notification.FeishuWebhook) == "" {
		log.Fatal("notification.feishu_webhook is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	alert := notify.BuildScanStartAlert("notify-test-scan", "raw", 1, cfg.Notification.FrontendBaseURL)
	alert.Title = "[Everywhere] Feishu webhook test"
	alert.Summary = "This is a direct webhook validation from the CLI."
	response, err := notify.SendFeishuLifecycleCard(ctx, cfg.Notification.FeishuWebhook, alert)
	if err != nil {
		log.Fatalf("send test notification: %v response=%s", err, response)
	}
	log.Printf("test notification sent successfully response=%s", response)
}

func waitForTaskCompletion(ctx context.Context, db *gorm.DB, taskID string) (database.ScanTask, []database.Pingback, []database.ResponseFinding, error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		var task database.ScanTask
		if err := db.First(&task, "id = ?", taskID).Error; err != nil {
			return database.ScanTask{}, nil, nil, err
		}

		switch strings.ToLower(strings.TrimSpace(task.Status)) {
		case "completed", "failed", "stopped":
			var pingbacks []database.Pingback
			if err := db.Where("scan_task_id = ?", taskID).Order("received_at desc").Find(&pingbacks).Error; err != nil {
				return task, nil, nil, err
			}
			var responseFindings []database.ResponseFinding
			if err := db.Where("scan_task_id = ?", taskID).Order("created_at desc").Find(&responseFindings).Error; err != nil {
				return task, nil, nil, err
			}
			return task, pingbacks, responseFindings, nil
		}

		select {
		case <-ctx.Done():
			return task, nil, nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func printSummary(task database.ScanTask, pingbacks []database.Pingback, responseFindings []database.ResponseFinding, asJSON bool) {
	if asJSON {
		summary := map[string]any{
			"task_id":                    task.ID,
			"status":                     task.Status,
			"mode":                       task.Mode,
			"targets":                    task.TargetCount,
			"estimated_requests":         task.EstimatedRequests,
			"requests_sent":              task.RequestSent,
			"pingback_count":             task.PingbackCount,
			"response_finding_count":     task.ResponseHitCount,
			"batch_count":                task.BatchCount,
			"completed_targets":          task.CompletedTargets,
			"current_stage":              task.CurrentStage,
			"started_at":                 task.StartedAt,
			"completed_at":               task.CompletedAt,
			"last_error":                 task.LastError,
			"oob_findings_by_payload":    countByPayload(pingbacks),
			"oob_findings_by_proto":      countByProtocol(pingbacks),
			"response_findings_by_key":   countResponseByPayload(responseFindings),
			"response_findings_by_conf":  countResponseByConfidence(responseFindings),
		}
		data, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println()
	fmt.Println("Scan Summary")
	fmt.Printf("Task ID: %s\n", task.ID)
	fmt.Printf("Status: %s\n", task.Status)
	fmt.Printf("Targets: %d\n", task.TargetCount)
	fmt.Printf("Requests sent: %d / %d\n", task.RequestSent, task.EstimatedRequests)
	fmt.Printf("Pingbacks: %d\n", task.PingbackCount)
	fmt.Printf("Response findings: %d\n", task.ResponseHitCount)
	if strings.TrimSpace(task.LastError) != "" {
		fmt.Printf("Last error: %s\n", task.LastError)
	}
	fmt.Println()
	fmt.Println("OOB Findings By Payload")
	for key, count := range countByPayload(pingbacks) {
		fmt.Printf("- %s: %d\n", key, count)
	}
	fmt.Println()
	fmt.Println("OOB Findings By Protocol")
	for key, count := range countByProtocol(pingbacks) {
		fmt.Printf("- %s: %d\n", key, count)
	}
	fmt.Println()
	fmt.Println("Response Findings By Payload")
	for key, count := range countResponseByPayload(responseFindings) {
		fmt.Printf("- %s: %d\n", key, count)
	}
	fmt.Println()
	fmt.Println("Response Findings By Confidence")
	for key, count := range countResponseByConfidence(responseFindings) {
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

func countResponseByPayload(results []database.ResponseFinding) map[string]int {
	counts := make(map[string]int)
	for _, item := range results {
		counts[item.PayloadKey]++
	}
	return counts
}

func countResponseByConfidence(results []database.ResponseFinding) map[string]int {
	counts := make(map[string]int)
	for _, item := range results {
		counts[item.Confidence]++
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
