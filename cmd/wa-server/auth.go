package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rverton/webanalyze/internal/apikeys"
)

const bearerPrefix = "Bearer "

func authAndRateLimitMiddleware(v *apikeys.Verifier, rl *redisLimiter, lf *lastUsedFlusher, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublicPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			t0 := time.Now()
			rid, _ := r.Context().Value(ctxRequestID).(string)
			routeLabel := r.Method + " " + r.URL.Path

			raw := strings.TrimSpace(r.Header.Get("Authorization"))
			if raw == "" || !strings.HasPrefix(strings.ToLower(raw), strings.ToLower(bearerPrefix)) {
				owner := ""
				waAuthAttempts.WithLabelValues("unauthorized", routeLabel, owner).Inc()
				waAuthDuration.Observe(time.Since(t0).Seconds())
				authLogJSON(log, rid, "unauthorized", "-", "", routeLabel, clientIP(r), r.UserAgent(), durationMs(t0))
				writeUnauthorized(w, rid)
				return
			}
			token := strings.TrimSpace(raw[len(bearerPrefix):])

			kc, err := v.Verify(r.Context(), token)
			if err != nil {
				waAuthAttempts.WithLabelValues("unauthorized", routeLabel, "").Inc()
				waAuthDuration.Observe(time.Since(t0).Seconds())
				authLogJSON(log, rid, "unauthorized", "-", "", routeLabel, clientIP(r), r.UserAgent(), durationMs(t0))
				writeUnauthorized(w, rid)
				return
			}

			keyPrefix := kc.Prefix
			if len(keyPrefix) > 12 {
				keyPrefix = keyPrefix[:12]
			}

			nowUnix := time.Now().Unix()
			burst := kc.RPSLimit * 2
			if burst < 1 {
				burst = 1
			}
			allowed, tokensLeft, retryRPS := rl.CheckRPS(r.Context(), kc.KeyID, kc.RPSLimit, burst, nowUnix)
			if !allowed {
				reset := nowUnix + retryRPS
				waRateLimitRejects.WithLabelValues("rps", kc.Owner).Inc()
				waAuthAttempts.WithLabelValues("rate_limited", routeLabel, kc.Owner).Inc()
				waAuthDuration.Observe(time.Since(t0).Seconds())
				authLogJSON(log, rid, "rate_limited", keyPrefix, kc.KeyID, routeLabel, clientIP(r), r.UserAgent(), durationMs(t0))
				write429RPS(w, rid, kc.RPSLimit, retryRPS, reset)
				return
			}

			rej, dailyRem, dailyErr := rl.DailyShouldReject(r.Context(), kc.KeyID, kc.DailyQuota)
			if dailyErr != nil {
				rej = false
				dailyRem = float64(kc.DailyQuota)
			}
			if rej {
				untilMid := utcNextMidnightUnix()
				sec := untilMid - nowUnix
				if sec < 1 {
					sec = 1
				}
				waRateLimitRejects.WithLabelValues("daily", kc.Owner).Inc()
				waAuthAttempts.WithLabelValues("rate_limited", routeLabel, kc.Owner).Inc()
				waAuthDuration.Observe(time.Since(t0).Seconds())
				authLogJSON(log, rid, "quota_exceeded", keyPrefix, kc.KeyID, routeLabel, clientIP(r), r.UserAgent(), durationMs(t0))
				write429Daily(w, rid, kc.RPSLimit, untilMid, sec)
				return
			}

			rem := &limitRemain{
				RPSLimit:       kc.RPSLimit,
				RPSRemaining:   tokensLeft,
				DailyLimit:     kc.DailyQuota,
				DailyRemaining: dailyRem,
			}
			ctx := context.WithValue(r.Context(), ctxKeyContext, kc)
			ctx = context.WithValue(ctx, ctxKeyRemain, rem)
			if lf != nil {
				lf.Enqueue(kc.KeyID)
			}
			waAuthAttempts.WithLabelValues("success", routeLabel, kc.Owner).Inc()
			waAuthDuration.Observe(time.Since(t0).Seconds())
			authLogJSON(log, rid, "success", keyPrefix, kc.KeyID, routeLabel, clientIP(r), r.UserAgent(), durationMs(t0))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func durationMs(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

func clientIP(r *http.Request) string {
	if h := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); h != "" {
		if idx := strings.IndexByte(h, ','); idx >= 0 {
			h = strings.TrimSpace(h[:idx])
		}
		if h != "" {
			return h
		}
	}
	return strings.TrimSpace(strings.Split(r.RemoteAddr, ":")[0])
}

func writeUnauthorized(w http.ResponseWriter, rid string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":       CodeUnauthorized,
			"message":    "Missing or invalid API key",
			"retryable":  false,
			"request_id": rid,
		},
	})
}

func write429RPS(w http.ResponseWriter, rid string, rps int, retryAfter int64, resetUnix int64) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rps))
	w.Header().Set("X-RateLimit-Remaining", "0")
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetUnix, 10))
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":       CodeRateLimited,
			"message":    "Too many requests",
			"retryable":  true,
			"request_id": rid,
		},
	})
}

func write429Daily(w http.ResponseWriter, rid string, rps int, resetUnix int64, retryAfter int64) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rps))
	w.Header().Set("X-RateLimit-Remaining", "0")
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetUnix, 10))
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":       CodeRateLimited,
			"message":    "Too many requests",
			"retryable":  true,
			"request_id": rid,
		},
	})
}

func authLogJSON(log *slog.Logger, reqID string, outcome, keyPrefix, keyID string, route, sourceIP, ua string, durMs int64) {
	if len(keyPrefix) > 12 {
		keyPrefix = keyPrefix[:12]
	}
	log.Info("auth",
		slog.String("event", "auth"),
		slog.String("request_id", reqID),
		slog.String("outcome", outcome),
		slog.String("key_prefix", keyPrefix),
		slog.String("key_id", keyID),
		slog.String("route", route),
		slog.String("source_ip", sourceIP),
		slog.String("user_agent", ua),
		slog.Int64("duration_ms", durMs),
	)
}
