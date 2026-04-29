package dnswhois

import (
	"context"
	"embed"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

//go:embed data/providers.json data/verification.json data/ip_ranges.json
var embeddedFS embed.FS

// SideRuntime holds shared resolver, taxonomy, RDAP client and Redis ref.
type SideRuntime struct {
	Resolver *Resolver
	RDAP     *RDAP
	Taxonomy *Taxonomy
	IPRanges *IPRanges
	Redis    *redis.Client

	WhoisTimeout  time.Duration
	WhoisCacheTTL time.Duration
	WhoisEnabled  bool

	muDNS sync.Mutex
}

// SideRuntimeConfig knobs from environment (see README).
type SideRuntimeConfig struct {
	DNSUpstreams      []string
	DNSTimeout        time.Duration
	DNSRetries        int
	DNSMaxCacheTTL    time.Duration
	WhoisTimeout      time.Duration
	WhoisCacheTTL     time.Duration
	HostingRangesPath string
	Redis             *redis.Client
	WhoisEnabled      bool
}

func NewSideRuntime(cfg SideRuntimeConfig) (*SideRuntime, error) {
	pj, err := embeddedFS.ReadFile("data/providers.json")
	if err != nil {
		return nil, err
	}
	vj, err := embeddedFS.ReadFile("data/verification.json")
	if err != nil {
		return nil, err
	}
	tax, err := LoadTaxonomy(pj, vj)
	if err != nil {
		return nil, err
	}

	ipRaw, err := embeddedFS.ReadFile("data/ip_ranges.json")
	if err != nil {
		return nil, err
	}
	if cfg.HostingRangesPath != "" {
		if b, err := os.ReadFile(cfg.HostingRangesPath); err == nil && len(b) > 0 {
			ipRaw = b
		}
	}
	ipRanges, err := ParseIPRangesJSON(ipRaw)
	if err != nil {
		return nil, err
	}

	wto := cfg.WhoisTimeout
	if wto <= 0 {
		wto = 5 * time.Second
	}
	dnsTimeout := cfg.DNSTimeout
	if dnsTimeout <= 0 {
		dnsTimeout = 2 * time.Second
	}
	maxTTL := cfg.DNSMaxCacheTTL
	if maxTTL <= 0 {
		maxTTL = 5 * time.Minute
	}
	res := NewResolver(cfg.DNSUpstreams, dnsTimeout, cfg.DNSRetries, maxTTL)
	rd := NewRDAP(wto)

	return &SideRuntime{
		Resolver:      res,
		RDAP:          rd,
		Taxonomy:      tax,
		IPRanges:      ipRanges,
		Redis:         cfg.Redis,
		WhoisTimeout:  wto,
		WhoisCacheTTL: cfg.WhoisCacheTTL,
		WhoisEnabled:  cfg.WhoisEnabled,
	}, nil
}

func (s *SideRuntime) ReloadDNSUpstreams(upstreams []string) {
	s.muDNS.Lock()
	defer s.muDNS.Unlock()
	s.Resolver.ReloadUpstreams(upstreams)
}

// GatherParallel runs HTTP fetchFn concurrently with DNS/WHOIS; waits for all before returning.
func (s *SideRuntime) GatherParallel(parent context.Context, apex, hostLabel string, skipDNS, skipWHOIS, fresh bool, fetchFn func() error, webIPs func() []string) SideEnvelope {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	var env SideEnvelope
	var wg sync.WaitGroup

	if s != nil && !skipDNS && s.Resolver != nil && s.Taxonomy != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wips := []string(nil)
			if webIPs != nil {
				wips = webIPs()
			}
			env.DNS = GatherDNS(ctx, s.Resolver, hostLabel, apex, s.Taxonomy, s.IPRanges, wips)
			ObserveDNS(env.DNS)
		}()
	}
	if s != nil && !skipWHOIS && s.WhoisEnabled && s.RDAP != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			block, dur, cached := GatherWHOIS(ctx, apex, s.RDAP, s.WhoisTimeout, s.Redis, s.WhoisCacheTTL, fresh)
			if block != nil && s.Taxonomy != nil {
				block.TaxonomyVer = s.Taxonomy.Version
			}
			env.WHOIS = block
			ObserveWHOIS(block, dur, cached)
		}()
	}

	_ = fetchFn()
	wg.Wait()
	return env
}
