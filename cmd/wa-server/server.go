package main

import (
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rverton/webanalyze"
	"github.com/rverton/webanalyze/internal/apikeys"
)

func buildHTTPHandler(cfg Config, db *sql.DB, wa *webanalyze.WebAnalyzer, pool *scanPool, st *serverState, v *apikeys.Verifier, rl *redisLimiter, lf *lastUsedFlusher, log *slog.Logger) http.Handler {
	humCfg := huma.DefaultConfig("Webanalyze API", webanalyze.VERSION)
	humCfg.OpenAPIPath = "/v1/openapi"
	humCfg.DocsPath = "/v1/docs"
	humCfg.SchemasPath = "/v1/schemas"
	if humCfg.OpenAPI.Info != nil {
		humCfg.OpenAPI.Info.Description = `Sync web technology detection API.

Authenticate with Authorization: Bearer wa_live_<secret> (see environment bootstrapping docs).

## Retry semantics (idempotency)

Write endpoints accept optional ` + "`Idempotency-Key`" + ` (1–255 ASCII). Retries with the same key and JSON body receive the cached status and body. If the original request is still running, the server responds with 409 ` + "`IDEMPOTENCY_IN_PROGRESS`" + ` and ` + "`Retry-After: 5`" + `; back off and retry. Reusing a key with a different body yields 422 ` + "`IDEMPOTENCY_KEY_CONFLICT`" + `. Server errors (5xx) are not cached. Recommended client policy: exponential backoff with jitter, respect ` + "`Retry-After`" + `, and use a stable key per logical operation (e.g. ULID).`
	}
	if humCfg.OpenAPI.Components != nil && humCfg.OpenAPI.Components.SecuritySchemes == nil {
		humCfg.OpenAPI.Components.SecuritySchemes = map[string]*huma.SecurityScheme{}
	}
	if humCfg.OpenAPI.Components != nil {
		humCfg.OpenAPI.Components.SecuritySchemes["bearerAuth"] = &huma.SecurityScheme{
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "wa_live_...",
			Description:  `API key in format wa_live_<24 base62><4 char checksum>. Obtained via ops CLI or WA_BOOTSTRAP_API_KEY on first deploy.`,
		}
	}

	mux := chi.NewRouter()
	mux.Handle("/metrics", promhttp.Handler())

	inner := chi.NewRouter()
	inner.Use(chimw.RealIP)
	api := humachi.New(inner, humCfg)

	registerHealth(api, st)
	registerAnalyze(api, cfg, wa, pool)
	registerBulkAnalyze(api, cfg, wa, pool)
	registerOpenAPIIdempotency(api)

	r := chi.NewRouter()
	r.Use(requestIDMiddleware)
	r.Use(peekAnalyzeHostMiddleware(256 * 1024))
	r.Use(recoverMiddleware(log))
	r.Use(authAndRateLimitMiddleware(v, rl, lf, log))
	r.Use(idempotencyMiddleware(newIdempotencyStore(rl.rawClient()), cfg.MaxBodyBytes, log))
	r.Use(quotaHeadersAndAccountingMiddleware(rl))
	r.Use(loggingMiddleware(log))
	r.Mount("/", inner)
	mux.Mount("/", r)
	return mux
}
