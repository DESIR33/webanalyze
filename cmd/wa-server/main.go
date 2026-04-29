package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rverton/webanalyze"
)

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	log := newLogger(cfg.LogLevel)

	ctx := context.Background()
	db, err := openKeysDB(ctx, cfg.DBPath)
	if err != nil {
		log.Error("keys db", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer db.Close()
	if err := migrateKeys(ctx, db); err != nil {
		log.Error("migrate keys", slog.String("err", err.Error()))
		os.Exit(1)
	}
	if err := seedAPIKeys(ctx, db, cfg.APIKeysEnv); err != nil {
		log.Error("seed api keys", slog.String("err", err.Error()))
		os.Exit(1)
	}

	techPath, err := resolveTechnologiesPath(cfg.TechFile)
	if err != nil {
		log.Error("technologies file", slog.String("err", err.Error()))
		os.Exit(1)
	}
	techFile, err := os.Open(techPath)
	if err != nil {
		log.Error("open technologies", slog.String("path", techPath), slog.String("err", err.Error()))
		os.Exit(1)
	}
	wa, err := webanalyze.NewWebAnalyzer(techFile, nil)
	techFile.Close()
	if err != nil {
		log.Error("webanalyzer init", slog.String("err", err.Error()))
		os.Exit(1)
	}

	pool := newScanPool(cfg.Workers)
	st := &serverState{ready: true}

	handler := buildHTTPHandler(cfg, db, wa, pool, st, log)

	addr := fmt.Sprintf(":%d", cfg.HTTPPort)
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(cfg.MaxTimeoutMS+5) * time.Millisecond,
		WriteTimeout:      time.Duration(cfg.MaxTimeoutMS+5) * time.Millisecond,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Info("listening", slog.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http server", slog.String("err", err.Error()))
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	pool.close()
	st.ready = false

	drain := time.Duration(cfg.ShutdownDrainSecs) * time.Second
	shutdownCtx, cancel := context.WithTimeout(context.Background(), drain)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", slog.String("err", err.Error()))
	}
	log.Info("stopped")
}

func resolveTechnologiesPath(configured string) (string, error) {
	if configured == "" {
		return "", fmt.Errorf("WA_TECH_FILE empty")
	}
	if filepath.IsAbs(configured) {
		return configured, nil
	}
	if _, err := os.Stat(configured); err == nil {
		abs, err := filepath.Abs(configured)
		if err != nil {
			return configured, nil
		}
		return abs, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	candidates := []string{
		filepath.Join(filepath.Dir(exe), configured),
		filepath.Join("/app", configured),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("technologies file not found: %s", configured)
}

func apiKeyMiddleware(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			if isPublicPath(p) {
				next.ServeHTTP(w, r)
				return
			}
			rid, _ := r.Context().Value(ctxRequestID).(string)
			kid, err := verifyBearer(r.Context(), db, r.Header.Get("Authorization"))
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{
						"code":       CodeUnauthorized,
						"message":    "Invalid or missing API key",
						"retryable":  false,
						"request_id": rid,
					},
				})
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyID, kid)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func isPublicPath(p string) bool {
	switch {
	case p == "/v1/health":
		return true
	case strings.HasPrefix(p, "/v1/openapi"):
		return true
	case p == "/v1/docs":
		return true
	case strings.HasPrefix(p, "/v1/schemas"):
		return true
	default:
		return false
	}
}
