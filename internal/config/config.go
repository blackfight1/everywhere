package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database     DatabaseConfig     `json:"database" yaml:"database"`
	Interactsh   InteractshConfig   `json:"interactsh" yaml:"interactsh"`
	Scanner      ScannerConfig      `json:"scanner" yaml:"scanner"`
	OwnIP        OwnIPConfig        `json:"own_ip" yaml:"own_ip"`
	Notification NotificationConfig `json:"notification" yaml:"notification"`
}

type DatabaseConfig struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Name     string `json:"name" yaml:"name"`
	User     string `json:"user" yaml:"user"`
	Password string `json:"password" yaml:"password"`
	SSLMode  string `json:"sslmode" yaml:"sslmode"`
}

type InteractshConfig struct {
	ServerURL string `json:"server_url" yaml:"server_url"`
	Token     string `json:"token" yaml:"token"`
}

type ScannerConfig struct {
	DefaultConcurrency   int `json:"default_concurrency" yaml:"default_concurrency"`
	DefaultBatchSize     int `json:"default_batch_size" yaml:"default_batch_size"`
	DefaultRateLimit     int `json:"default_rate_limit" yaml:"default_rate_limit"`
	DefaultTimeoutMinute int `json:"default_timeout_minutes" yaml:"default_timeout_minutes"`
}

type OwnIPConfig struct {
	Action string `json:"action" yaml:"action"`
}

type NotificationConfig struct {
	Enabled       bool   `json:"enabled" yaml:"enabled"`
	FeishuWebhook string `json:"feishu_webhook" yaml:"feishu_webhook"`
}

func Default() Config {
	return Config{
		Database: DatabaseConfig{
			Host:     "127.0.0.1",
			Port:     5432,
			Name:     "hass",
			User:     "hass",
			Password: "changeme",
			SSLMode:  "disable",
		},
		Interactsh: InteractshConfig{},
		Scanner: ScannerConfig{
			DefaultConcurrency:   10,
			DefaultBatchSize:     1500,
			DefaultRateLimit:     20,
			DefaultTimeoutMinute: 1440,
		},
		OwnIP: OwnIPConfig{
			Action: "mark",
		},
		Notification: NotificationConfig{},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, err
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, err
		}
	}

	overrideString(&cfg.Database.Host, "DB_HOST")
	overrideInt(&cfg.Database.Port, "DB_PORT")
	overrideString(&cfg.Database.Name, "DB_NAME")
	overrideString(&cfg.Database.User, "DB_USER")
	overrideString(&cfg.Database.Password, "DB_PASSWORD")
	overrideString(&cfg.Database.SSLMode, "DB_SSLMODE")
	overrideString(&cfg.Interactsh.ServerURL, "INTERACTSH_SERVER")
	overrideString(&cfg.Interactsh.Token, "INTERACTSH_TOKEN")
	overrideInt(&cfg.Scanner.DefaultConcurrency, "SCANNER_DEFAULT_CONCURRENCY")
	overrideInt(&cfg.Scanner.DefaultBatchSize, "SCANNER_DEFAULT_BATCH_SIZE")
	overrideInt(&cfg.Scanner.DefaultRateLimit, "SCANNER_DEFAULT_RATE_LIMIT")
	overrideInt(&cfg.Scanner.DefaultTimeoutMinute, "SCANNER_DEFAULT_TIMEOUT_MINUTES")
	overrideString(&cfg.OwnIP.Action, "OWN_IP_ACTION")
	overrideBool(&cfg.Notification.Enabled, "NOTIFY_ENABLED")
	overrideString(&cfg.Notification.FeishuWebhook, "FEISHU_WEBHOOK")

	cfg.OwnIP.Action = strings.ToLower(strings.TrimSpace(cfg.OwnIP.Action))
	if cfg.OwnIP.Action == "" {
		cfg.OwnIP.Action = "mark"
	}
	if cfg.Scanner.DefaultBatchSize <= 0 {
		cfg.Scanner.DefaultBatchSize = 1500
	}

	return cfg, nil
}

func Save(path string, cfg Config) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("config path is empty")
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshal config yaml: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	tempFile, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tempPath := tempFile.Name()
	cleanup := func() {
		_ = os.Remove(tempPath)
	}

	if _, err := tempFile.Write(data); err != nil {
		_ = tempFile.Close()
		cleanup()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Chmod(tempPath, 0o600); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		cleanup()
		return fmt.Errorf("replace config file: %w", err)
	}
	return nil
}

func (c Config) PostgresDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.User,
		c.Database.Password,
		c.Database.Name,
		c.Database.SSLMode,
	)
}

func overrideString(target *string, key string) {
	if value, ok := os.LookupEnv(key); ok {
		*target = value
	}
}

func overrideInt(target *int, key string) {
	if value, ok := os.LookupEnv(key); ok {
		parsed, err := strconv.Atoi(value)
		if err == nil {
			*target = parsed
		}
	}
}

func overrideBool(target *bool, key string) {
	if value, ok := os.LookupEnv(key); ok {
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			*target = parsed
		}
	}
}
