package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func recoverMiddleware(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					rid, _ := r.Context().Value(ctxRequestID).(string)
					structuredPanicLog(rid, r.URL.Path, rec)
					log.Error("handler panic", slog.Any("panic", rec), slog.String("request_id", rid), slog.String("path", r.URL.Path))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"error": map[string]any{
							"code":       CodeInternal,
							"message":    "internal server error",
							"retryable":  false,
							"request_id": rid,
						},
					})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
