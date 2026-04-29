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
	waAsyncSubmittedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "wa_async_submitted_total",
			Help: "Async analyze jobs accepted by owner label",
		},
		[]string{"owner"},
	)
	waAsyncStatusTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "wa_async_status_total",
			Help: "Async job terminal outcomes",
		},
		[]string{"outcome"},
	)
	waAsyncQueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "wa_async_queue_depth",
			Help: "Number of jobs in queued state",
		},
	)
	waAsyncRunSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "wa_async_run_seconds",
			Help:    "Wall time of async scan execution per leased job",
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 16),
		},
	)
	waWebhookAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "wa_webhook_attempts_total",
			Help: "Webhook delivery attempts by outcome bucket",
		},
		[]string{"outcome"},
	)
	waWebhookDeliveryAttemptsToSuccess = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "wa_webhook_delivery_attempts_to_success",
			Help:    "Delivery attempt count when webhook succeeds",
			Buckets: []float64{1, 2, 3, 4, 5, 6},
		},
	)
	waWebhookDeadLetteredTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "wa_webhook_dead_lettered_total",
			Help: "Jobs or deliveries that entered dead letter / exhausted state",
		},
		[]string{"reason"},
	)
)
