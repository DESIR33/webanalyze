package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestOpenAPI_IdempotencyHeadersDocumented(t *testing.T) {
	cfg := Config{
		Workers:           2,
		DefaultTimeoutMS:  5000,
		MaxTimeoutMS:      10000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	h, _ := newTestHandler(t, cfg, "", true, 50, 200_000)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/openapi.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	analyze := paths["/v1/analyze"].(map[string]any)
	post := analyze["post"].(map[string]any)
	params := post["parameters"].([]any)
	var hasIdem bool
	for _, p := range params {
		m := p.(map[string]any)
		if m["name"] == "Idempotency-Key" {
			hasIdem = true
			break
		}
	}
	if !hasIdem {
		t.Fatal("OpenAPI missing Idempotency-Key parameter on POST /v1/analyze")
	}
	if _, ok := post["responses"].(map[string]any)["409"]; !ok {
		t.Fatal("OpenAPI missing 409 response")
	}
	if _, ok := post["responses"].(map[string]any)["422"]; !ok {
		t.Fatal("OpenAPI missing 422 response")
	}
}

func TestIdempotencyMiddleware_PresentOnV1POST_AbsentOnReadPaths(t *testing.T) {
	cfg := Config{
		Workers:           2,
		DefaultTimeoutMS:  3000,
		MaxTimeoutMS:      5000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	s := miniredis.RunT(t)
	h, key := newTestHandler(t, cfg, "redis://"+s.Addr(), true, 50, 200_000)
	auth := "Bearer " + key

	idem := "01JIDEMPOTENCYPATHCHARTESTV1"

	t.Run("health ignores idempotency", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
		req.Header.Set("Idempotency-Key", idem)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d", rec.Code)
		}
		if rec.Header().Get("X-Idempotency-Replayed") != "" {
			t.Fatal("read path should not set idempotency headers")
		}
	})

	t.Run("analyze post sets idempotency headers on fresh", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<html><body>x</body></html>`)
		}))
		defer ts.Close()

		body := `{"url":"` + ts.URL + `"}`
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		req.Header.Set("Idempotency-Key", idem+"-fresh")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
		if rec.Header().Get("X-Idempotency-Replayed") != "false" {
			t.Fatalf("replay header: %q", rec.Header().Get("X-Idempotency-Replayed"))
		}
		if rec.Header().Get("X-Idempotency-Stored") != "true" {
			t.Fatalf("stored: %q", rec.Header().Get("X-Idempotency-Stored"))
		}
	})
}

func TestIdempotency_ReplaySameBody(t *testing.T) {
	cfg := Config{
		Workers:           2,
		DefaultTimeoutMS:  3000,
		MaxTimeoutMS:      5000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	s := miniredis.RunT(t)
	h, key := newTestHandler(t, cfg, "redis://"+s.Addr(), true, 50, 200_000)
	auth := "Bearer " + key

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body><meta name="generator" content="WordPress 6.0"/></body></html>`)
	}))
	defer ts.Close()

	idem := "01JIDEMREPLAYTEST0001"
	body := "{\n  \"url\": \"" + ts.URL + "\"\n}"

	do := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		req.Header.Set("Idempotency-Key", idem)
		h.ServeHTTP(rec, req)
		return rec
	}

	r1 := do()
	if r1.Code != http.StatusOK {
		t.Fatalf("first %d %s", r1.Code, r1.Body.String())
	}
	r2 := do()
	if r2.Code != http.StatusOK {
		t.Fatalf("second %d %s", r2.Code, r2.Body.String())
	}
	if r2.Header().Get("X-Idempotency-Replayed") != "true" {
		t.Fatalf("expected replay true, got %q", r2.Header().Get("X-Idempotency-Replayed"))
	}
	orig := r1.Header().Get("X-Request-Id")
	if r2.Header().Get("X-Idempotency-Original-Request-Id") != orig {
		t.Fatalf("original req id: want %q got %q", orig, r2.Header().Get("X-Idempotency-Original-Request-Id"))
	}
	b1 := r1.Body.Bytes()
	b2 := r2.Body.Bytes()
	var j1, j2 map[string]any
	_ = json.Unmarshal(b1, &j1)
	_ = json.Unmarshal(b2, &j2)
	if j1["input_url"] != j2["input_url"] || j1["final_url"] != j2["final_url"] {
		t.Fatalf("body mismatch: %#v vs %#v", j1["input_url"], j2["input_url"])
	}
	if r2.Header().Get("X-Idempotency-First-Seen-At") == "" {
		t.Fatal("missing first seen")
	}
}

func TestIdempotency_KeyConflict(t *testing.T) {
	cfg := Config{
		Workers:           2,
		DefaultTimeoutMS:  3000,
		MaxTimeoutMS:      5000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	s := miniredis.RunT(t)
	h, key := newTestHandler(t, cfg, "redis://"+s.Addr(), true, 50, 200_000)
	auth := "Bearer " + key

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body>ok</body></html>`)
	}))
	defer ts.Close()

	idem := "01JIDEMCONFLICT00001"
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(`{"url":"`+ts.URL+`"}`))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Authorization", auth)
	req1.Header.Set("Idempotency-Key", idem)
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first %d", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(`{"url":"http://127.0.0.1:9/"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", auth)
	req2.Header.Set("Idempotency-Key", idem)
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422 got %d %s", rec2.Code, rec2.Body.String())
	}
	assertCode(t, rec2.Body.Bytes(), CodeIdempotencyKeyConflict)
}

func TestIdempotency_InvalidKeyAndPayload(t *testing.T) {
	cfg := Config{
		Workers:           2,
		DefaultTimeoutMS:  3000,
		MaxTimeoutMS:      5000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	s := miniredis.RunT(t)
	h, key := newTestHandler(t, cfg, "redis://"+s.Addr(), true, 50, 200_000)
	auth := "Bearer " + key

	t.Run("key too long", func(t *testing.T) {
		long := strings.Repeat("a", 256)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(`{"url":"https://example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		req.Header.Set("Idempotency-Key", long)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("got %d", rec.Code)
		}
		assertCode(t, rec.Body.Bytes(), CodeInvalidIdempotencyKey)
	})

	t.Run("non-json body", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(`not json`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		req.Header.Set("Idempotency-Key", "01JVALIDKEY000000001")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("got %d", rec.Code)
		}
		assertCode(t, rec.Body.Bytes(), CodeInvalidPayload)
	})
}

func TestIdempotency_Deterministic4xxCached(t *testing.T) {
	cfg := Config{
		Workers:           2,
		DefaultTimeoutMS:  3000,
		MaxTimeoutMS:      5000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	s := miniredis.RunT(t)
	h, key := newTestHandler(t, cfg, "redis://"+s.Addr(), true, 50, 200_000)
	auth := "Bearer " + key
	idem := "01JIDEM4XXCACHE00001"
	body := `{"url":"not-a-url"}`

	do := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		req.Header.Set("Idempotency-Key", idem)
		h.ServeHTTP(rec, req)
		return rec
	}
	r1 := do()
	if r1.Code != http.StatusBadRequest {
		t.Fatalf("first %d", r1.Code)
	}
	r2 := do()
	if r2.Code != http.StatusBadRequest {
		t.Fatalf("second %d", r2.Code)
	}
	if r2.Header().Get("X-Idempotency-Replayed") != "true" {
		t.Fatal("expected cached 4xx replay")
	}
}

func TestIdempotency_ConcurrentSameKey_HandlerRunsOnce(t *testing.T) {
	cfg := Config{
		Workers:           8,
		DefaultTimeoutMS:  15000,
		MaxTimeoutMS:      20000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	s := miniredis.RunT(t)
	h, key := newTestHandler(t, cfg, "redis://"+s.Addr(), true, 100, 200_000)
	auth := "Bearer " + key

	var hits int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		time.Sleep(400 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body>slow</body></html>`)
	}))
	defer ts.Close()

	idem := "01JIDEMRACE0000000001"
	body := []byte(`{"url":"` + ts.URL + `"}`)

	results := make(chan int, 30)
	for i := 0; i < 30; i++ {
		go func() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/analyze", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", auth)
			req.Header.Set("Idempotency-Key", idem)
			h.ServeHTTP(rec, req)
			results <- rec.Code
		}()
	}
	ok := 0
	conflict := 0
	other := 0
	for i := 0; i < 30; i++ {
		switch c := <-results; c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
		default:
			other++
		}
	}
	if other != 0 {
		t.Fatalf("unexpected status codes (non-200/409): %d", other)
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("handler hits want 1 got %d", hits)
	}
	if ok != 1 {
		t.Fatalf("want exactly one 200, got %d", ok)
	}
	if conflict != 29 {
		t.Fatalf("want 29 409 in_progress, got %d", conflict)
	}
}

func TestIdempotency_InProgressSequential(t *testing.T) {
	cfg := Config{
		Workers:           2,
		DefaultTimeoutMS:  8000,
		MaxTimeoutMS:      10000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	s := miniredis.RunT(t)
	h, key := newTestHandler(t, cfg, "redis://"+s.Addr(), true, 50, 200_000)
	auth := "Bearer " + key

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body>x</body></html>`)
	}))
	defer ts.Close()

	idem := "01JIDEMINPROG0000001"
	body := `{"url":"` + ts.URL + `"}`

	errCh := make(chan error, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		req.Header.Set("Idempotency-Key", idem)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			errCh <- fmt.Errorf("background %d %s", rec.Code, rec.Body.String())
			return
		}
		close(errCh)
	}()

	time.Sleep(50 * time.Millisecond)
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", auth)
	req2.Header.Set("Idempotency-Key", idem)
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("want 409 during inflight, got %d %s", rec2.Code, rec2.Body.String())
	}
	assertCode(t, rec2.Body.Bytes(), CodeIdempotencyInProgress)
	if rec2.Header().Get("Retry-After") != "5" {
		t.Fatalf("Retry-After %q", rec2.Header().Get("Retry-After"))
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
