package main

import (
	"encoding/json"
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

type keyLimiter struct {
	mu        sync.Mutex
	perMinute int
	lim       map[string]*rate.Limiter
}

func newKeyLimiter(perMinute int) *keyLimiter {
	return &keyLimiter{perMinute: perMinute, lim: make(map[string]*rate.Limiter)}
}

func (k *keyLimiter) limiterFor(keyID string) *rate.Limiter {
	k.mu.Lock()
	defer k.mu.Unlock()
	l, ok := k.lim[keyID]
	if !ok {
		if k.perMinute <= 0 {
			return rate.NewLimiter(rate.Inf, 1)
		}
		lim := rate.NewLimiter(rate.Limit(float64(k.perMinute)/60.0), k.perMinute)
		k.lim[keyID] = lim
		l = lim
	}
	return l
}

func rateLimitMiddleware(k *keyLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if k == nil || k.perMinute <= 0 || isPublicPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			kid, ok := r.Context().Value(ctxKeyID).(string)
			if !ok || kid == "" {
				next.ServeHTTP(w, r)
				return
			}
			lim := k.limiterFor(kid)
			if !lim.Allow() {
				rid, _ := r.Context().Value(ctxRequestID).(string)
				w.Header().Set("Retry-After", "60")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{
						"code":       CodeRateLimited,
						"message":    "Too many requests",
						"retryable":  true,
						"request_id": rid,
					},
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
