package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Database   DatabaseConfig   `yaml:"database"`
	Interactsh InteractshConfig `yaml:"interactsh"`
	Scanner    ScannerConfig    `yaml:"scanner"`
	OwnIP      OwnIPConfig      `yaml:"own_ip"`
}

type ServerConfig struct {
	Listen string `yaml:"listen"`
}

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Name     string `yaml:"name"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	SSLMode  string `yaml:"sslmode"`
}

type InteractshConfig struct {
	ServerURL string `yaml:"server_url"`
	Token     string `yaml:"token"`
}

type ScannerConfig struct {
	DefaultConcurrency   int    `yaml:"default_concurrency"`
	DefaultRateLimit     int    `yaml:"default_rate_limit"`
	DefaultTimeoutMinute int    `yaml:"default_timeout_minutes"`
	DefaultOrigin        string `yaml:"default_origin"`
	DefaultReferer       string `yaml:"default_referer"`
}

type OwnIPConfig struct {
	Action string `yaml:"action"`
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
