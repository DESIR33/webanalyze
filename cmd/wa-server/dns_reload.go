package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/rverton/webanalyze/internal/dnswhois"
)

func dnsUpstreamReloader(ctx context.Context, cfg Config, rt *dnswhois.SideRuntime, log *slog.Logger) {
	if rt == nil {
		return
	}
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	var last string
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cur := strings.TrimSpace(os.Getenv("WA_DNS_UPSTREAMS"))
			if cur == "" {
				cur = "1.1.1.1,8.8.8.8"
			}
			if cur == last {
				continue
			}
			last = cur
			rt.ReloadDNSUpstreams(parseCSVList(cur))
			log.Info("dns_upstream_reload", slog.String("wa_dns_upstreams", cur))
		}
	}
}
