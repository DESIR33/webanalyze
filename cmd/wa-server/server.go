package main

import (
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rverton/webanalyze"
)

func buildHTTPHandler(cfg Config, db *sql.DB, wa *webanalyze.WebAnalyzer, pool *scanPool, st *serverState, log *slog.Logger) http.Handler {
	humCfg := huma.DefaultConfig("Webanalyze API", webanalyze.VERSION)
	humCfg.OpenAPIPath = "/v1/openapi"
	humCfg.DocsPath = "/v1/docs"
	humCfg.SchemasPath = "/v1/schemas"
	if humCfg.OpenAPI.Info != nil {
		humCfg.OpenAPI.Info.Description = "Sync web technology detection API. Authenticate with Authorization: Bearer <key_id>:<secret>."
	}
	if humCfg.OpenAPI.Components != nil && humCfg.OpenAPI.Components.SecuritySchemes == nil {
		humCfg.OpenAPI.Components.SecuritySchemes = map[string]*huma.SecurityScheme{}
	}
	if humCfg.OpenAPI.Components != nil {
		humCfg.OpenAPI.Components.SecuritySchemes["bearerAuth"] = &huma.SecurityScheme{
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "keyId:secret",
			Description:  "Use the raw token format keyId:secret after Bearer.",
		}
	}

	inner := chi.NewRouter()
	inner.Use(chimw.RealIP)
	api := humachi.New(inner, humCfg)

	registerHealth(api, st)
	registerAnalyze(api, cfg, wa, pool)

	kLimiter := newKeyLimiter(cfg.RateLimitPerMin)
	r := chi.NewRouter()
	r.Use(requestIDMiddleware)
	r.Use(peekAnalyzeHostMiddleware(256 * 1024))
	r.Use(recoverMiddleware(log))
	r.Use(apiKeyMiddleware(db))
	r.Use(rateLimitMiddleware(kLimiter))
	r.Use(loggingMiddleware(log))
	r.Mount("/", inner)
	return r
}