package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rverton/webanalyze"
	"github.com/rverton/webanalyze/internal/dnswhois"
)

// AnalyzeOptions mirrors request body options.
type AnalyzeOptions struct {
	TimeoutMS         int    `json:"timeout_ms,omitempty" minimum:"1" maximum:"30000" doc:"Per-request timeout in milliseconds"`
	FollowRedirects   *bool  `json:"follow_redirects,omitempty"`
	CrawlDepth        int    `json:"crawl_depth,omitempty" minimum:"0" maximum:"10"`
	IncludeSubdomains *bool  `json:"include_subdomains,omitempty"`
	UserAgent         string `json:"user_agent,omitempty" doc:"Use \"default\" for server default"`
	SkipDNS           *bool  `json:"skip_dns,omitempty" doc:"Skip DNS side-channel enrichment"`
	SkipWHOIS         *bool  `json:"skip_whois,omitempty" doc:"Skip WHOIS/RDAP enrichment"`
	Fresh             bool   `json:"fresh,omitempty" doc:"Bypass WHOIS cache (same as query fresh on sync analyze)"`
}

// AnalyzeRequestBody is POST /v1/analyze body.
type AnalyzeRequestBody struct {
	URL     string         `json:"url" format:"uri" doc:"Full URL including scheme (https recommended)"`
	Options AnalyzeOptions `json:"options,omitempty"`
}

// TechnologyItem is one detected stack entry.
type TechnologyItem struct {
	Name       string   `json:"name"`
	Slug       string   `json:"slug"`
	Version    string   `json:"version,omitempty"`
	Categories []string `json:"categories"`
	Confidence int      `json:"confidence" minimum:"0" maximum:"100"`
	Evidence   []string `json:"evidence"`
}

// AnalyzeStats holds fetch and fingerprint counters for an analyze response.
type AnalyzeStats struct {
	FetchStatus           int `json:"fetch_status"`
	HTMLBytes             int `json:"html_bytes"`
	FingerprintsEvaluated int `json:"fingerprints_evaluated"`
}

// AnalyzeSuccessResponse is the JSON body for 200 responses from POST /v1/analyze.
type AnalyzeSuccessResponse struct {
	RequestID    string               `json:"request_id"`
	InputURL     string               `json:"input_url"`
	FinalURL     string               `json:"final_url"`
	ScannedAt    time.Time            `json:"scanned_at"`
	DurationMS   int64                `json:"duration_ms"`
	Technologies []TechnologyItem     `json:"technologies"`
	Stats        AnalyzeStats         `json:"stats"`
	DNS          *dnswhois.DNSBlock   `json:"dns,omitempty"`
	WHOIS        *dnswhois.WHOISBlock `json:"whois,omitempty"`
}

func confidenceFromMatches(matchSlices [][]string) int {
	n := 0
	for _, m := range matchSlices {
		n += len(m)
	}
	if n <= 0 {
		return 0
	}
	c := 50 + n*5
	if c > 100 {
		c = 100
	}
	return c
}

func evidenceStrings(matchSlices [][]string, maxN int) []string {
	var out []string
	for _, row := range matchSlices {
		for _, cell := range row {
			s := strings.TrimSpace(cell)
			if s != "" {
				out = append(out, s)
				if len(out) >= maxN {
					return out
				}
			}
		}
	}
	return out
}

func defaultHTTPTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          128,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func buildHTTPClient(timeout time.Duration, followRedirects bool, initialURL string, cfg Config) *http.Client {
	tr := defaultHTTPTransport().Clone()
	var rt http.RoundTripper = tr
	if cfg.TargetPerHostRPM > 0 {
		rt = newHostPolitenessTransport(
			tr,
			cfg.TargetHostLRUSize,
			float64(cfg.TargetPerHostRPM),
			float64(cfg.TargetPerHostBurst),
			cfg.TargetHostFailThreshold,
			cfg.TargetHostCooldown,
			cfg.TargetHostAcquireTimeout,
		)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: rt,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !followRedirects {
				return http.ErrUseLastResponse
			}
			u0, err := url.Parse(initialURL)
			if err != nil {
				return http.ErrUseLastResponse
			}
			if u0.Hostname() != req.URL.Hostname() {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func ptrBool(v bool) *bool { return &v }

func mapMatchesToTech(wa *webanalyze.WebAnalyzer, res webanalyze.Result) []TechnologyItem {
	out := make([]TechnologyItem, 0, len(res.Matches))
	for _, m := range res.Matches {
		cats := make([]string, 0, len(m.App.Cats))
		for _, cid := range m.App.Cats {
			if name := wa.CategoryById(string(cid)); name != "" {
				cats = append(cats, name)
			}
		}
		item := TechnologyItem{
			Name:       m.AppName,
			Slug:       strings.ToLower(strings.ReplaceAll(m.AppName, " ", "-")),
			Version:    m.Version,
			Categories: cats,
			Confidence: confidenceFromMatches(m.Matches),
			Evidence:   evidenceStrings(m.Matches, 20),
		}
		out = append(out, item)
	}
	return out
}

func runAnalyzeScan(ctx context.Context, reqID string, cfg Config, wa *webanalyze.WebAnalyzer, pool *scanPool, sideRT *dnswhois.SideRuntime, u *url.URL, rawURL string, opts AnalyzeOptions, fresh bool) (*AnalyzeSuccessResponse, error) {
	timeoutMS := cfg.DefaultTimeoutMS
	if opts.TimeoutMS > 0 {
		timeoutMS = opts.TimeoutMS
	}
	if timeoutMS > cfg.MaxTimeoutMS {
		timeoutMS = cfg.MaxTimeoutMS
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond

	follow := false
	if opts.FollowRedirects != nil {
		follow = *opts.FollowRedirects
	}

	includeSub := false
	if opts.IncludeSubdomains != nil {
		includeSub = *opts.IncludeSubdomains
	}

	ua := strings.TrimSpace(opts.UserAgent)
	if ua == "" || ua == "default" {
		ua = "Mozilla/5.0 (compatible; WebanalyzeAPI/1.0; +https://github.com/rverton/webanalyze)"
	}

	job := webanalyze.NewOnlineJob(u.String(), "", nil, opts.CrawlDepth, includeSub, follow)
	job.MaxHTMLBytes = cfg.MaxHTMLBytes
	job.UserAgent = ua

	client := buildHTTPClient(timeout, follow, u.String(), cfg)

	acquireCtx, cancel := context.WithTimeout(ctx, timeout+2*time.Second)
	defer cancel()

	if err := pool.acquire(acquireCtx); err != nil {
		return nil, errTyped(503, CodeInternal, "Server is shutting down or overloaded", true, reqID)
	}
	defer pool.release()

	skipDNS := opts.SkipDNS != nil && *opts.SkipDNS
	skipWHOIS := opts.SkipWHOIS != nil && *opts.SkipWHOIS

	apex, _ := dnswhois.ApexFromHost(u.Hostname())
	if apex == "" {
		apex = dnswhois.NormalizeHost(u.Hostname())
	}
	hostLabel := dnswhois.NormalizeHost(u.Hostname())

	var res webanalyze.Result
	var side dnswhois.SideEnvelope
	if sideRT != nil {
		side = sideRT.GatherParallel(ctx, apex, hostLabel, skipDNS, skipWHOIS, fresh, func() error {
			r, _ := wa.ProcessWithClient(job, client)
			res = r
			return nil
		}, nil)
	} else {
		r, _ := wa.ProcessWithClient(job, client)
		res = r
	}

	if res.Error != nil {
		return nil, classifyScanError(reqID, res.Error)
	}

	final := res.FinalURL
	if final == "" {
		final = res.Host
	}

	return &AnalyzeSuccessResponse{
		InputURL:     rawURL,
		FinalURL:     final,
		ScannedAt:    time.Now().UTC().Truncate(time.Millisecond),
		DurationMS:   res.Duration.Milliseconds(),
		Technologies: mapMatchesToTech(wa, res),
		Stats: AnalyzeStats{
			FetchStatus:           res.FetchStatus,
			HTMLBytes:             res.HTMLBytes,
			FingerprintsEvaluated: res.FingerprintsEvaluated,
		},
		DNS:   side.DNS,
		WHOIS: side.WHOIS,
	}, nil
}

func registerAnalyze(api huma.API, cfg Config, wa *webanalyze.WebAnalyzer, pool *scanPool, sideRT *dnswhois.SideRuntime, log *slog.Logger) {
	type Input struct {
		RequestID string `header:"X-Request-ID" doc:"Optional correlation ID; echoed in response"`
		Fresh     bool   `query:"fresh" doc:"Bypass WHOIS cache when true"`
		Body      AnalyzeRequestBody
	}

	type Output struct {
		RequestIDHeader string `header:"X-Request-ID"`
		Body            func(huma.Context)
	}

	huma.Register(api, huma.Operation{
		OperationID:  "analyze",
		Method:       http.MethodPost,
		Path:         "/v1/analyze",
		Summary:      "Analyze a URL and return detected technologies",
		Tags:         []string{"Analyze"},
		MaxBodyBytes: cfg.MaxBodyBytes,
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
	}, func(ctx context.Context, input *Input) (*Output, error) {
		reqID := strings.TrimSpace(input.RequestID)
		if reqID == "" {
			reqID = newRequestID()
		}

		rawURL := strings.TrimSpace(input.Body.URL)
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, errTyped(400, CodeInvalidURL, "url must be an absolute http or https URL", false, reqID)
		}

		payload, scanErr := runAnalyzeScan(ctx, reqID, cfg, wa, pool, sideRT, u, rawURL, input.Body.Options, input.Fresh || input.Body.Options.Fresh)
		if scanErr != nil {
			var te *TypedHTTPError
			if errors.As(scanErr, &te) && te.Payload.RequestID == "" {
				te.Payload.RequestID = reqID
			}
			return nil, scanErr
		}
		payload.RequestID = reqID

		logAnalyzeSideChannel(log, reqID, payload.DNS, payload.WHOIS)

		return &Output{
			RequestIDHeader: reqID,
			Body: func(hctx huma.Context) {
				hctx.SetHeader("Content-Type", "application/json")
				_ = json.NewEncoder(hctx.BodyWriter()).Encode(payload)
			},
		}, nil
	})
}
