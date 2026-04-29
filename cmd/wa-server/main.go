package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/rverton/webanalyze"
	"github.com/rverton/webanalyze/internal/apikeys"
	"github.com/rverton/webanalyze/internal/asyncjobs"
	_ "modernc.org/sqlite"
)

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	log := newLogger(cfg.LogLevel)

	baseCtx, stopBase := context.WithCancel(context.Background())
	defer stopBase()
	st, err := apikeys.OpenStore(baseCtx, cfg.DBPath, cfg.DatabaseURL)
	if err != nil {
		log.Error("keys db", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer st.Close()
	if err := st.Migrate(baseCtx); err != nil {
		log.Error("migrate keys", slog.String("err", err.Error()))
		os.Exit(1)
	}
	if err := asyncjobs.Migrate(baseCtx, st.DB(), st.Postgres()); err != nil {
		log.Error("migrate async jobs", slog.String("err", err.Error()))
		os.Exit(1)
	}
	if err := apikeys.BootstrapFromEnv(baseCtx, st, cfg.BootstrapAPIKey, cfg.BootstrapOwner, cfg.BootstrapKeyName, cfg.BootstrapCreatedBy); err != nil {
		log.Error("bootstrap api key", slog.String("err", err.Error()))
		os.Exit(1)
	}
	nkeys, _ := st.CountKeys(baseCtx)
	if nkeys == 0 {
		log.Error("no api keys in database — set WA_BOOTSTRAP_API_KEY or create keys via webanalyze keys create")
		os.Exit(1)
	}

	v, err := apikeys.NewVerifier(st)
	if err != nil {
		log.Error("auth verifier", slog.String("err", err.Error()))
		os.Exit(1)
	}

	rl, err := newRedisLimiter(cfg.RedisURL)
	if err != nil {
		log.Error("redis", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer rl.Close()

	lf := startLastUsedFlusher(st)
	defer lf.Close()

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
	stReady := &serverState{ready: true}

	ajs := asyncjobs.NewStore(st.DB(), st.Postgres())
	asyncRT := startAsyncRuntime(baseCtx, cfg, ajs, wa, pool, log)

	handler := buildHTTPHandler(cfg, ajs, wa, pool, stReady, v, rl, lf, log)

	addr := fmt.Sprintf(":%d", cfg.HTTPPort)
	writeMS := cfg.MaxTimeoutMS + 5
	// Bulk batches may run up to ceil(N/workers) * per-URL work; cap wall-clock for HTTP write deadline.
	bulkWriteMS := cfg.MaxBulkURLs * (cfg.MaxTimeoutMS + 5000)
	if bulkWriteMS > 3_600_000 {
		bulkWriteMS = 3_600_000
	}
	if bulkWriteMS > writeMS {
		writeMS = bulkWriteMS
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(cfg.MaxTimeoutMS+5) * time.Millisecond,
		WriteTimeout:      time.Duration(writeMS) * time.Millisecond,
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
	if asyncRT != nil {
		asyncRT.Stop()
	}
	stReady.ready = false

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
	case p == "/metrics":
		return true
	default:
		return false
	}
}
