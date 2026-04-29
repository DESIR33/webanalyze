package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// peekAnalyzeHostMiddleware reads a bounded prefix of POST /v1/analyze JSON to log target host only (restores body).
func peekAnalyzeHostMiddleware(maxPeek int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/analyze" {
				next.ServeHTTP(w, r)
				return
			}
			if r.Body == nil {
				next.ServeHTTP(w, r)
				return
			}
			peek, err := io.ReadAll(io.LimitReader(r.Body, int64(maxPeek)))
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			rest, err := io.ReadAll(r.Body)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			full := append(peek, rest...)
			r.Body = io.NopCloser(bytes.NewReader(full))

			var partial struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(peek, &partial)
			host := "-"
			if partial.URL != "" {
				if h := hostOnlyFromURLString(partial.URL); h != "" {
					host = h
				}
			}
			ctx := context.WithValue(r.Context(), ctxTargetHost, host)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), ctxRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeTooLarge(w http.ResponseWriter, rid string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":       CodeInternal,
			"message":    "request body exceeds configured limit",
			"retryable":  false,
			"request_id": rid,
		},
	})
}

func loggingMiddleware(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)

			reqID, _ := r.Context().Value(ctxRequestID).(string)
			kctx := ctxKeyFromContext(r.Context())
			keyID := kctx.KeyID
			if keyID == "" {
				keyID = "-"
			}
			th := "-"
			if v, ok := r.Context().Value(ctxTargetHost).(string); ok && v != "" {
				th = v
			}
			logRequest(log, reqID, keyID, r.URL.Path, ww.Status(), time.Since(start).Milliseconds(), th)
		})
	}
}
