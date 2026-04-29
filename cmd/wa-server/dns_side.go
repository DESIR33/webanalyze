package main

import (
	"log/slog"
	"strings"
	"time"

	"github.com/rverton/webanalyze/internal/dnswhois"
)

func newSideRuntime(cfg Config, rl *redisLimiter) (*dnswhois.SideRuntime, error) {
	rc := rl.rawClient()
	return dnswhois.NewSideRuntime(dnswhois.SideRuntimeConfig{
		DNSUpstreams:      cfg.DNSUpstreams,
		DNSTimeout:        time.Duration(cfg.DNSTimeoutMS) * time.Millisecond,
		DNSRetries:        cfg.DNSRetries,
		DNSMaxCacheTTL:    time.Duration(cfg.DNSCacheMaxTTLs) * time.Second,
		WhoisTimeout:      time.Duration(cfg.WHOISTimeoutMS) * time.Millisecond,
		WhoisCacheTTL:     time.Duration(cfg.WHOISCacheTTLHrs) * time.Hour,
		HostingRangesPath: cfg.HostingRangesPath,
		Redis:             rc,
		WhoisEnabled:      cfg.WHOISEnabled,
	})
}

func logAnalyzeSideChannel(log *slog.Logger, reqID string, dns *dnswhois.DNSBlock, who *dnswhois.WHOISBlock) {
	if log == nil {
		return
	}
	var mailP, dnsP, hostP string
	var dnsMS, whoMS int64
	var errs []string
	if dns != nil {
		mailP = dns.Derived.MailProvider
		dnsP = dns.Derived.DNSProvider
		hostP = dns.Derived.HostingProviderHint
		dnsMS = dns.DurationMS
		for _, e := range dns.Errors {
			errs = append(errs, "dns:"+e.Record+":"+e.Code)
		}
	}
	if who != nil {
		whoMS = who.DurationMS
		for _, e := range who.Errors {
			errs = append(errs, "whois:"+e.Code)
		}
	}
	log.Info("analyze_side_channel",
		slog.String("request_id", reqID),
		slog.String("mail_provider", mailP),
		slog.String("dns_provider", dnsP),
		slog.String("hosting_provider_hint", hostP),
		slog.Int64("dns_duration_ms", dnsMS),
		slog.Int64("whois_duration_ms", whoMS),
		slog.String("side_errors", strings.Join(errs, ",")),
		slog.Time("timestamp", time.Now().UTC()),
	)
}
