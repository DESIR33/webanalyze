package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

func newLogger(level string) *slog.Logger {
	lvl := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	return slog.New(h)
}

func logRequest(log *slog.Logger, requestID, keyID, route string, status int, durationMs int64, host string) {
	log.Info("request",
		slog.String("request_id", requestID),
		slog.String("key_id", keyID),
		slog.String("route", route),
		slog.Int("status", status),
		slog.Int64("duration_ms", durationMs),
		slog.String("target_url_host", host),
		slog.Time("timestamp", time.Now().UTC()),
	)
}

func structuredPanicLog(requestID, route string, recovered any) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"level":      "error",
		"msg":        "panic recovered",
		"request_id": requestID,
		"route":      route,
		"panic":      fmt.Sprintf("%v", recovered),
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
	})
}
