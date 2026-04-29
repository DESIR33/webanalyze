package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
)

func quotaHeadersAndAccountingMiddleware(rl *redisLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublicPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			kctx := ctxKeyFromContext(r.Context())
			if kctx.KeyID == "" {
				next.ServeHTTP(w, r)
				return
			}
			if rem, ok := r.Context().Value(ctxKeyRemain).(*limitRemain); ok && rem != nil {
				w.Header().Set("X-RateLimit-Limit-RPS", strconv.Itoa(rem.RPSLimit))
				w.Header().Set("X-RateLimit-Remaining-RPS", strconv.FormatFloat(rem.RPSRemaining, 'f', 2, 64))
				w.Header().Set("X-RateLimit-Limit-Daily", strconv.Itoa(rem.DailyLimit))
				w.Header().Set("X-RateLimit-Remaining-Daily", strconv.FormatFloat(rem.DailyRemaining, 'f', 2, 64))
			}
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			if strings.EqualFold(ww.Header().Get("X-Idempotency-Replayed"), "true") {
				return
			}
			st := ww.Status()
			counted := (st >= 200 && st < 400) || (st >= 500 && st < 600)
			if counted {
				_ = rl.IncrementDailyCounted(context.Background(), kctx.KeyID, 1)
			}
		})
	}
}
