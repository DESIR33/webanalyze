package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds process-level settings from the environment.
type Config struct {
	HTTPPort           int
	Workers            int
	DefaultTimeoutMS   int
	MaxTimeoutMS       int
	MaxBodyBytes       int64
	MaxBulkURLs        int
	MaxHTMLBytes       int
	ShutdownDrainSecs  int
	TechFile           string
	DBPath             string // SQLite file DSN fragment when WA_DATABASE_URL is empty
	DatabaseURL        string // WA_DATABASE_URL (Postgres) takes precedence over SQLite
	RedisURL           string // WA_REDIS_URL (empty = rate limits + idempotency fail-open)
	BootstrapAPIKey    string // WA_BOOTSTRAP_API_KEY wa_live_... first boot only
	BootstrapOwner     string // WA_BOOTSTRAP_OWNER
	BootstrapKeyName   string // WA_BOOTSTRAP_KEY_NAME
	BootstrapCreatedBy string // WA_BOOTSTRAP_CREATED_BY
	LogLevel           string

	// Per-target-host outbound politeness (0 RPM = disabled).
	TargetPerHostRPM         int
	TargetPerHostBurst       int
	TargetHostFailThreshold  int
	TargetHostCooldown       time.Duration
	TargetHostAcquireTimeout time.Duration
	TargetHostLRUSize        int
}

func getenv(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func getenvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getenvInt64(key string, def int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

// LoadConfig reads configuration from the environment.
func LoadConfig() (Config, error) {
	cfg := Config{
		HTTPPort:           getenvInt("WA_HTTP_PORT", 8080),
		Workers:            getenvInt("WA_WORKERS", 16),
		DefaultTimeoutMS:   getenvInt("WA_DEFAULT_TIMEOUT_MS", 10000),
		MaxTimeoutMS:       getenvInt("WA_MAX_TIMEOUT_MS", 30000),
		MaxBodyBytes:       getenvInt64("WA_MAX_BODY_BYTES", 5_000_000),
		MaxBulkURLs:        getenvInt("WA_MAX_BULK_URLS", 100),
		MaxHTMLBytes:       getenvInt("WA_MAX_HTML_BYTES", 5_000_000),
		ShutdownDrainSecs:  getenvInt("WA_SHUTDOWN_DRAIN_SECS", 25),
		TechFile:           getenv("WA_TECH_FILE", "technologies.json"),
		DBPath:             getenv("WA_DB_PATH", ""),
		DatabaseURL:        os.Getenv("WA_DATABASE_URL"),
		RedisURL:           os.Getenv("WA_REDIS_URL"),
		BootstrapAPIKey:    os.Getenv("WA_BOOTSTRAP_API_KEY"),
		BootstrapOwner:     getenv("WA_BOOTSTRAP_OWNER", "bootstrap"),
		BootstrapKeyName:   getenv("WA_BOOTSTRAP_KEY_NAME", "bootstrap"),
		BootstrapCreatedBy: getenv("WA_BOOTSTRAP_CREATED_BY", "env"),
		LogLevel:           getenv("WA_LOG_LEVEL", "info"),

		TargetPerHostRPM:        getenvInt("WA_TARGET_PER_HOST_RPM", 60),
		TargetPerHostBurst:      getenvInt("WA_TARGET_PER_HOST_BURST", 10),
		TargetHostFailThreshold: getenvInt("WA_TARGET_HOST_FAIL_THRESHOLD", 5),
		TargetHostLRUSize:       getenvInt("WA_TARGET_HOST_LRU", 10_000),
	}
	cooldownSecs := getenvInt("WA_TARGET_HOST_COOLDOWN_SECS", 60)
	if cooldownSecs < 1 {
		cooldownSecs = 60
	}
	cfg.TargetHostCooldown = time.Duration(cooldownSecs) * time.Second

	acqMS := getenvInt("WA_TARGET_HOST_ACQUIRE_TIMEOUT_MS", 0)
	if acqMS <= 0 {
		acqMS = cfg.MaxTimeoutMS + 2000
		if acqMS > 120_000 {
			acqMS = 120_000
		}
	}
	cfg.TargetHostAcquireTimeout = time.Duration(acqMS) * time.Millisecond

	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.HTTPPort < 1 || cfg.HTTPPort > 65535 {
		return Config{}, fmt.Errorf("WA_HTTP_PORT invalid")
	}
	if cfg.DefaultTimeoutMS < 1 {
		cfg.DefaultTimeoutMS = 10000
	}
	if cfg.MaxTimeoutMS < cfg.DefaultTimeoutMS {
		cfg.MaxTimeoutMS = cfg.DefaultTimeoutMS
	}
	if cfg.MaxHTMLBytes < 1 {
		cfg.MaxHTMLBytes = 5_000_000
	}
	if cfg.MaxBodyBytes < 1024 {
		cfg.MaxBodyBytes = 1024
	}
	if cfg.MaxBulkURLs < 1 {
		cfg.MaxBulkURLs = 1
	}
	if cfg.MaxBulkURLs > 500 {
		cfg.MaxBulkURLs = 500
	}
	if cfg.TargetPerHostRPM > 0 {
		if cfg.TargetPerHostBurst < 1 {
			cfg.TargetPerHostBurst = 1
		}
		if cfg.TargetHostFailThreshold < 1 {
			cfg.TargetHostFailThreshold = 1
		}
		if cfg.TargetHostLRUSize < 1 {
			cfg.TargetHostLRUSize = 1
		}
	}
	return cfg, nil
}
