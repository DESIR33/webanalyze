package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHostPolitenessTransport_RateLimitBurst(t *testing.T) {
	var calls atomic.Int32
	next := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})

	tr := newHostPolitenessTransport(next, 100, 2, 1, 5, time.Minute, 50*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "http://slow.example/", nil)
	_, err := tr.RoundTrip(req.Clone(req.Context()))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err = tr.RoundTrip(req.Clone(req.Context()))
	if err == nil {
		t.Fatal("expected rate limit on second immediate request")
	}
	if !errors.Is(err, errTargetHostRateLimited) {
		t.Fatalf("want rate limited, got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("next called %d times, want 1", calls.Load())
	}
}

func TestHostPolitenessTransport_CircuitOpens(t *testing.T) {
	var calls atomic.Int32
	next := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 500, Body: http.NoBody}, nil
	})

	tr := newHostPolitenessTransport(next, 100, 600, 30, 3, time.Hour, 5*time.Second)

	req := httptest.NewRequest(http.MethodGet, "http://dead.example/", nil)
	for i := 0; i < 3; i++ {
		_, _ = tr.RoundTrip(req.Clone(req.Context()))
	}
	if calls.Load() != 3 {
		t.Fatalf("calls before open: %d", calls.Load())
	}

	_, err := tr.RoundTrip(req.Clone(req.Context()))
	if err == nil {
		t.Fatal("expected circuit open")
	}
	if !errors.Is(err, errTargetHostCircuitOpen) {
		t.Fatalf("want circuit open, got %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("fourth request should not reach next, calls=%d", calls.Load())
	}
}

func TestHostPolitenessTransport_SuccessResetsFailures(t *testing.T) {
	var status atomic.Int32
	status.Store(500)
	next := roundTripFunc(func(*http.Request) (*http.Response, error) {
		code := status.Load()
		return &http.Response{StatusCode: int(code), Body: http.NoBody}, nil
	})

	tr := newHostPolitenessTransport(next, 100, 600, 30, 3, time.Hour, 5*time.Second)
	req := httptest.NewRequest(http.MethodGet, "http://flaky.example/", nil)

	for i := 0; i < 2; i++ {
		_, _ = tr.RoundTrip(req.Clone(req.Context()))
	}
	status.Store(200)
	_, _ = tr.RoundTrip(req.Clone(req.Context()))
	status.Store(500)
	for i := 0; i < 3; i++ {
		_, _ = tr.RoundTrip(req.Clone(req.Context()))
	}

	_, err := tr.RoundTrip(req.Clone(req.Context()))
	if err == nil {
		t.Fatal("expected circuit after 3 failures after success reset")
	}
	if !errors.Is(err, errTargetHostCircuitOpen) {
		t.Fatalf("got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
