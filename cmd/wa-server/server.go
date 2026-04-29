package main

import (
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rverton/webanalyze"
	"github.com/rverton/webanalyze/internal/apikeys"
	"github.com/rverton/webanalyze/internal/asyncjobs"
	"github.com/rverton/webanalyze/internal/dnswhois"
)

func buildHTTPHandler(cfg Config, js *asyncjobs.Store, wa *webanalyze.WebAnalyzer, pool *scanPool, st *serverState, v *apikeys.Verifier, rl *redisLimiter, lf *lastUsedFlusher, log *slog.Logger, sideRT *dnswhois.SideRuntime) http.Handler {
	humCfg := huma.DefaultConfig("Webanalyze API", webanalyze.VERSION)
	humCfg.OpenAPIPath = "/v1/openapi"
	humCfg.DocsPath = "/v1/docs"
	humCfg.SchemasPath = "/v1/schemas"
	if humCfg.OpenAPI.Info != nil {
		humCfg.OpenAPI.Info.Description = `Sync and asynchronous web technology detection API.

Authenticate with Authorization: Bearer wa_live_<secret> (see environment bootstrapping docs).

## Async jobs and webhooks

` + "`POST /v1/analyze/async`" + ` accepts a scan request and returns 202 with a ` + "`job_id`" + `. Poll ` + "`GET /v1/jobs/{id}`" + ` or receive a webhook when the job finishes.

Webhook ` + "`POST`" + ` body: ` + "`{ \"id\", \"type\": job.succeeded|job.failed, \"created_at\", \"job\": { ... same shape as GET job } }`" + `.

Headers: ` + "`Content-Type: application/json`" + `, ` + "`Webanalyze-Event-Id`" + `, ` + "`Webanalyze-Timestamp`" + ` (unix seconds), ` + "`Webanalyze-Signature: t=<ts>,v1=<hex>`" + ` where v1 is HMAC-SHA256(secret, \"<ts>.\" + rawBody) hex-encoded, ` + "`Webanalyze-Delivery-Attempt`" + ` (1-based).

Verification: reject if ` + "`|now - timestamp| > 300s`" + `; recompute HMAC and constant-time compare. Duplicates: use ` + "`Webanalyze-Event-Id`" + `.

### Webhook retry policy

Success: HTTP 2xx within 10s. Retries with full jitter over nominal delays before each retry: immediate, 30s, 2m, 10m, 1h, 6h (six attempts total). HTTP 410 Gone stops retries immediately. After exhaustion the job is ` + "`dead_lettered`" + ` (if callback configured); result remains available via GET until retention expires.

## Retry semantics (idempotency)

Write endpoints accept optional ` + "`Idempotency-Key`" + ` (1–255 ASCII). Retries with the same key and JSON body receive the cached status and body. If the original request is still running, the server responds with 409 ` + "`IDEMPOTENCY_IN_PROGRESS`" + ` and ` + "`Retry-After: 5`" + `; back off and retry. Reusing a key with a different body yields 422 ` + "`IDEMPOTENCY_KEY_CONFLICT`" + `. Server errors (5xx) are not cached. Recommended client policy: exponential backoff with jitter, respect ` + "`Retry-After`" + `, and use a stable key per logical operation (e.g. ULID).

` + "`POST /v1/analyze/async`" + ` uses application-level idempotency (same key replays the original job) and does not use Redis idempotency caching for that route.
`
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
	registerAnalyze(api, cfg, wa, pool, sideRT, log)
	registerBulkAnalyze(api, cfg, wa, pool, sideRT)
	registerAsyncRoutes(api, cfg, js, log)
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
