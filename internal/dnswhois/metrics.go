package dnswhois

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	waDNSLookups = promauto.NewCounterVec(
		prometheus.CounterOpts{Name: "wa_dns_lookups_total", Help: "DNS lookups by record and outcome"},
		[]string{"record", "outcome"},
	)
	waDNSLookupSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "wa_dns_lookup_seconds",
			Help:    "DNS lookup duration per logical record group",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 14),
		},
		[]string{"record"},
	)
	waWhoisLookups = promauto.NewCounterVec(
		prometheus.CounterOpts{Name: "wa_whois_lookups_total", Help: "WHOIS lookups by source and outcome"},
		[]string{"source", "outcome"},
	)
	waWhoisLookupSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "wa_whois_lookup_seconds",
			Help:    "WHOIS lookup wall time",
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 16),
		},
	)
	waWhoisCacheHit  = promauto.NewCounter(prometheus.CounterOpts{Name: "wa_whois_cache_hit_total", Help: "WHOIS cache hits"})
	waWhoisCacheMiss = promauto.NewCounter(prometheus.CounterOpts{Name: "wa_whois_cache_miss_total", Help: "WHOIS cache misses"})
	waDNSProvider    = promauto.NewCounterVec(
		prometheus.CounterOpts{Name: "wa_dns_provider_total", Help: "Derived dns_provider counts"},
		[]string{"provider"},
	)
	waMailProvider = promauto.NewCounterVec(
		prometheus.CounterOpts{Name: "wa_mail_provider_total", Help: "Derived mail_provider counts"},
		[]string{"provider"},
	)
)

// ObserveDNS updates Prometheus from a DNS block (best-effort).
func ObserveDNS(block *DNSBlock) {
	if block == nil {
		return
	}
	outcome := "success"
	if len(block.Errors) > 0 {
		outcome = "partial"
	}
	for k, ms := range block.RecordDurMS {
		waDNSLookupSeconds.WithLabelValues(k).Observe(float64(ms) / 1000)
		waDNSLookups.WithLabelValues(k, outcome).Inc()
	}
	if block.Derived.DNSProvider != "" {
		waDNSProvider.WithLabelValues(block.Derived.DNSProvider).Inc()
	}
	if block.Derived.MailProvider != "" {
		waMailProvider.WithLabelValues(block.Derived.MailProvider).Inc()
	}
}

// ObserveWHOIS updates Prometheus for WHOIS path.
func ObserveWHOIS(block *WHOISBlock, dur time.Duration, cached bool) {
	if cached {
		waWhoisCacheHit.Inc()
	} else {
		waWhoisCacheMiss.Inc()
	}
	src := "unknown"
	outcome := "success"
	if block != nil {
		src = block.Source
		if src == "" {
			src = "unknown"
		}
		if len(block.Errors) > 0 {
			outcome = "error"
		}
	} else {
		outcome = "empty"
	}
	waWhoisLookups.WithLabelValues(src, outcome).Inc()
	waWhoisLookupSeconds.Observe(dur.Seconds())
}
