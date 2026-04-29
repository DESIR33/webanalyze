package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/simplelru"
)

var (
	errTargetHostCircuitOpen = errors.New("target host circuit breaker is open")
	errTargetHostRateLimited = errors.New("target host rate limit exceeded for this request")
)

// hostPolitenessTransport wraps an HTTP transport with a per-host token bucket and circuit breaker.
type hostPolitenessTransport struct {
	next http.RoundTripper

	mu    sync.Mutex
	cache *lru.LRU[string, *hostGate]

	rpm            float64
	burst          float64
	failThreshold  int
	cooldown       time.Duration
	acquireTimeout time.Duration
}

func newHostPolitenessTransport(next http.RoundTripper, maxHosts int, rpm, burst float64, failThreshold int, cooldown, acquireTimeout time.Duration) *hostPolitenessTransport {
	if maxHosts < 1 {
		maxHosts = 1
	}
	cache, _ := lru.NewLRU[string, *hostGate](maxHosts, nil)
	return &hostPolitenessTransport{
		next:           next,
		cache:          cache,
		rpm:            rpm,
		burst:          burst,
		failThreshold:  failThreshold,
		cooldown:       cooldown,
		acquireTimeout: acquireTimeout,
	}
}

func (t *hostPolitenessTransport) gateFor(host string) *hostGate {
	t.mu.Lock()
	defer t.mu.Unlock()
	if g, ok := t.cache.Get(host); ok {
		return g
	}
	g := newHostGate(t.rpm, t.burst, t.failThreshold, t.cooldown)
	_ = t.cache.Add(host, g)
	return g
}

func (t *hostPolitenessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.next == nil {
		return nil, errors.New("host politeness transport misconfigured")
	}
	host := strings.ToLower(strings.TrimSpace(req.URL.Hostname()))
	if host == "" {
		return t.next.RoundTrip(req)
	}
	g := t.gateFor(host)

	if err := g.acquire(req.Context(), t.acquireTimeout); err != nil {
		return nil, err
	}

	resp, err := t.next.RoundTrip(req)
	g.recordOutcome(err, resp)
	return resp, err
}

type hostGate struct {
	mu sync.Mutex

	rpmPerSec     float64
	burst         float64
	failThreshold int
	cooldown      time.Duration

	tokens         float64
	lastRefill     time.Time
	consecFailures int
	openUntil      time.Time // when Before(now) is false, circuit allows traffic (closed / half-open)
}

func newHostGate(rpm, burst float64, failThreshold int, cooldown time.Duration) *hostGate {
	if burst < 1 {
		burst = 1
	}
	if failThreshold < 1 {
		failThreshold = 1
	}
	now := time.Now()
	return &hostGate{
		rpmPerSec:     rpm / 60.0,
		burst:         burst,
		failThreshold: failThreshold,
		cooldown:      cooldown,
		tokens:        burst,
		lastRefill:    now,
	}
}

func (g *hostGate) refill(now time.Time) {
	if g.rpmPerSec <= 0 {
		g.tokens = g.burst
		return
	}
	elapsed := now.Sub(g.lastRefill)
	if elapsed <= 0 {
		return
	}
	g.lastRefill = now
	g.tokens += elapsed.Seconds() * g.rpmPerSec
	if g.tokens > g.burst {
		g.tokens = g.burst
	}
}

func (g *hostGate) acquire(ctx context.Context, acquireTimeout time.Duration) error {
	deadline, hasDeadline := ctx.Deadline()
	acquireUntil := time.Now().Add(acquireTimeout)
	if hasDeadline && deadline.Before(acquireUntil) {
		acquireUntil = deadline
	}

	for {
		now := time.Now()
		if now.After(acquireUntil) {
			return fmt.Errorf("%w", errTargetHostRateLimited)
		}

		g.mu.Lock()
		if now.Before(g.openUntil) {
			g.mu.Unlock()
			return fmt.Errorf("%w", errTargetHostCircuitOpen)
		}

		g.refill(now)

		if g.tokens >= 1 {
			g.tokens -= 1
			g.mu.Unlock()
			return nil
		}

		wait := time.Until(acquireUntil)
		if g.rpmPerSec > 0 {
			need := 1 - g.tokens
			if need < 0 {
				need = 0
			}
			tokWait := time.Duration(need/g.rpmPerSec*float64(time.Second)) + time.Millisecond
			if tokWait < wait {
				wait = tokWait
			}
		}
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		g.mu.Unlock()

		tm := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			tm.Stop()
			return ctx.Err()
		case <-tm.C:
		}
	}
}

func (g *hostGate) recordOutcome(rtErr error, resp *http.Response) {
	failed := isOutboundFailure(rtErr, resp)

	g.mu.Lock()
	defer g.mu.Unlock()

	if !failed {
		g.consecFailures = 0
		return
	}

	g.consecFailures++
	if g.consecFailures >= g.failThreshold {
		g.openUntil = time.Now().Add(g.cooldown)
		g.consecFailures = 0
	}
}

func isOutboundFailure(rtErr error, resp *http.Response) bool {
	if rtErr != nil {
		return true
	}
	if resp == nil {
		return true
	}
	code := resp.StatusCode
	if code >= 500 {
		return true
	}
	if code == http.StatusTooManyRequests {
		return true
	}
	return false
}
