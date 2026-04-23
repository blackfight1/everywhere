package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server       ServerConfig       `json:"server" yaml:"server"`
	Database     DatabaseConfig     `json:"database" yaml:"database"`
	Interactsh   InteractshConfig   `json:"interactsh" yaml:"interactsh"`
	Scanner      ScannerConfig      `json:"scanner" yaml:"scanner"`
	OwnIP        OwnIPConfig        `json:"own_ip" yaml:"own_ip"`
	Notification NotificationConfig `json:"notification" yaml:"notification"`
}

type ServerConfig struct {
	Listen string `json:"listen" yaml:"listen"`
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
	DefaultConcurrency   int    `json:"default_concurrency" yaml:"default_concurrency"`
	DefaultRateLimit     int    `json:"default_rate_limit" yaml:"default_rate_limit"`
	DefaultTimeoutMinute int    `json:"default_timeout_minutes" yaml:"default_timeout_minutes"`
	DefaultOrigin        string `json:"default_origin" yaml:"default_origin"`
	DefaultReferer       string `json:"default_referer" yaml:"default_referer"`
}

type OwnIPConfig struct {
	Action string `json:"action" yaml:"action"`
}

type NotificationConfig struct {
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	FeishuWebhook   string `json:"feishu_webhook" yaml:"feishu_webhook"`
	FrontendBaseURL string `json:"frontend_base_url" yaml:"frontend_base_url"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			Listen: ":8080",
		},
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

	overrideString(&cfg.Server.Listen, "LISTEN")
	overrideString(&cfg.Database.Host, "DB_HOST")
	overrideInt(&cfg.Database.Port, "DB_PORT")
	overrideString(&cfg.Database.Name, "DB_NAME")
	overrideString(&cfg.Database.User, "DB_USER")
	overrideString(&cfg.Database.Password, "DB_PASSWORD")
	overrideString(&cfg.Database.SSLMode, "DB_SSLMODE")
	overrideString(&cfg.Interactsh.ServerURL, "INTERACTSH_SERVER")
	overrideString(&cfg.Interactsh.Token, "INTERACTSH_TOKEN")
	overrideInt(&cfg.Scanner.DefaultConcurrency, "SCANNER_DEFAULT_CONCURRENCY")
	overrideInt(&cfg.Scanner.DefaultRateLimit, "SCANNER_DEFAULT_RATE_LIMIT")
	overrideInt(&cfg.Scanner.DefaultTimeoutMinute, "SCANNER_DEFAULT_TIMEOUT_MINUTES")
	overrideString(&cfg.Scanner.DefaultOrigin, "SCANNER_DEFAULT_ORIGIN")
	overrideString(&cfg.Scanner.DefaultReferer, "SCANNER_DEFAULT_REFERER")
	overrideString(&cfg.OwnIP.Action, "OWN_IP_ACTION")
	overrideBool(&cfg.Notification.Enabled, "NOTIFY_ENABLED")
	overrideString(&cfg.Notification.FeishuWebhook, "FEISHU_WEBHOOK")
	overrideString(&cfg.Notification.FrontendBaseURL, "NOTIFY_FRONTEND_BASE_URL")

	cfg.OwnIP.Action = strings.ToLower(strings.TrimSpace(cfg.OwnIP.Action))
	if cfg.OwnIP.Action == "" {
		cfg.OwnIP.Action = "mark"
	}

	return cfg, nil
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
