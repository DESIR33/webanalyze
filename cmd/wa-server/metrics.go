package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	waAuthAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "wa_auth_attempts_total",
			Help: "Auth attempts by outcome, route, and owner label",
		},
		[]string{"outcome", "route", "owner"},
	)
	waRateLimitRejects = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "wa_rate_limit_rejects_total",
			Help: "Rate limit rejections by kind and owner",
		},
		[]string{"kind", "owner"},
	)
	waAuthDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "wa_auth_duration_seconds",
			Help:    "Time spent in auth and rate limit path",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 16),
		},
	)
	waIdempotencyRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "wa_idempotency_requests_total",
			Help: "Idempotency middleware outcomes when Idempotency-Key is present",
		},
		[]string{"outcome"},
	)
	waIdempotencyReplaySavingsSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "wa_idempotency_replay_savings_seconds",
			Help:    "Approximate compute seconds saved by serving a cached idempotent response",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 18),
		},
	)
	waIdempotencyLockExpired = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "wa_idempotency_lock_expired_total",
			Help: "Times a completing idempotent request found no Redis entry (lock TTL or race)",
		},
	)
)
