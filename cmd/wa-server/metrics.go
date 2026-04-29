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
)
