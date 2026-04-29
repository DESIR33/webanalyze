package dnswhois

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Resolver performs DNS queries via configurable upstreams only (never /etc/resolv.conf).
type Resolver struct {
	upstreams []string
	timeout   time.Duration
	retries   int
	cache     *ttlDNSCache
	client    *dns.Client
	mu        sync.RWMutex
	rrIdx     uint32
}

func NewResolver(upstreams []string, timeout time.Duration, retries int, maxCacheTTL time.Duration) *Resolver {
	u := make([]string, 0, len(upstreams))
	for _, s := range upstreams {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, ":") {
			s = net.JoinHostPort(s, "53")
		}
		u = append(u, s)
	}
	if len(u) == 0 {
		u = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	if retries < 0 {
		retries = 0
	}
	return &Resolver{
		upstreams: u,
		timeout:   timeout,
		retries:   retries,
		cache:     newTTLDNSCache(maxCacheTTL),
		client:    &dns.Client{Net: "udp", UDPSize: 4096},
	}
}

func (r *Resolver) ReloadUpstreams(upstreams []string) {
	u := make([]string, 0, len(upstreams))
	for _, s := range upstreams {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, ":") {
			s = net.JoinHostPort(s, "53")
		}
		u = append(u, s)
	}
	if len(u) == 0 {
		u = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	r.mu.Lock()
	r.upstreams = u
	r.mu.Unlock()
}

func (r *Resolver) pickServer() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.upstreams) == 0 {
		return "1.1.1.1:53"
	}
	i := atomic.AddUint32(&r.rrIdx, 1)
	return r.upstreams[int(i)%len(r.upstreams)]
}

// Exchange runs a DNS query with caching and retries.
func (r *Resolver) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	if len(msg.Question) != 1 {
		return nil, 0, errors.New("dnswhois: single question required")
	}
	q := msg.Question[0]
	cacheKey := fmt.Sprintf("%d:%s:%s", msg.MsgHdr.Opcode, q.Name, dns.TypeToString[q.Qtype])
	if cached, ttl, ok := r.cache.get(cacheKey); ok {
		return cached, ttl, nil
	}

	var lastErr error
	for attempt := 0; attempt <= r.retries; attempt++ {
		server := r.pickServer()
		cctx, cancel := context.WithTimeout(ctx, r.timeout)
		resp, _, err := r.client.ExchangeContext(cctx, msg, server)
		cancel()
		if err == nil && resp != nil {
			ttl := extractMinTTL(resp)
			r.cache.set(cacheKey, resp, ttl)
			return resp, ttl, nil
		}
		lastErr = err
		if attempt < r.retries {
			continue
		}
	}
	return nil, 0, lastErr
}

func extractMinTTL(resp *dns.Msg) time.Duration {
	if resp == nil {
		return 0
	}
	var minSec uint32 = ^uint32(0)
	for _, rr := range resp.Answer {
		h := rr.Header()
		if h.Ttl < minSec {
			minSec = h.Ttl
		}
	}
	for _, rr := range resp.Ns {
		h := rr.Header()
		if h.Ttl < minSec {
			minSec = h.Ttl
		}
	}
	for _, rr := range resp.Extra {
		h := rr.Header()
		if h.Ttl < minSec {
			minSec = h.Ttl
		}
	}
	if minSec == ^uint32(0) {
		return 0
	}
	return time.Duration(minSec) * time.Second
}

func fqdn(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}
