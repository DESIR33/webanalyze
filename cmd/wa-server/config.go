package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds process-level settings from the environment.
type Config struct {
	HTTPPort          int
	Workers           int
	DefaultTimeoutMS  int
	MaxTimeoutMS      int
	MaxBodyBytes      int64
	MaxHTMLBytes      int
	ShutdownDrainSecs int
	TechFile          string
	DBPath            string
	APIKeysEnv        string // WA_API_KEYS format: id:key,id:key
	LogLevel          string
	RateLimitPerMin   int // WA_RATE_LIMIT_PER_MINUTE, 0 disables
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
		HTTPPort:          getenvInt("WA_HTTP_PORT", 8080),
		Workers:           getenvInt("WA_WORKERS", 16),
		DefaultTimeoutMS:  getenvInt("WA_DEFAULT_TIMEOUT_MS", 10000),
		MaxTimeoutMS:      getenvInt("WA_MAX_TIMEOUT_MS", 30000),
		MaxBodyBytes:      getenvInt64("WA_MAX_BODY_BYTES", 5_000_000),
		MaxHTMLBytes:      getenvInt("WA_MAX_HTML_BYTES", 5_000_000),
		ShutdownDrainSecs: getenvInt("WA_SHUTDOWN_DRAIN_SECS", 25),
		TechFile:          getenv("WA_TECH_FILE", "technologies.json"),
		DBPath:            getenv("WA_DB_PATH", ""),
		APIKeysEnv:        os.Getenv("WA_API_KEYS"),
		LogLevel:          getenv("WA_LOG_LEVEL", "info"),
		RateLimitPerMin:   getenvInt("WA_RATE_LIMIT_PER_MINUTE", 0),
	}
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
	return cfg, nil
}
