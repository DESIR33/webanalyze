package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/rverton/webanalyze"
	"github.com/rverton/webanalyze/internal/apikeys"
)

func testTechnologiesPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(wd, "..", "technologies.json")
	if _, err := os.Stat(p); err != nil {
		t.Skip("technologies.json not found:", p)
	}
	return p
}

// newTestHandler builds a handler with optional miniredis URL (empty = no Redis, RPS/daily fail-open).
func newTestHandler(t *testing.T, cfg Config, redisAddr string, insertKey bool, rpsLimit, dailyQuota int) (http.Handler, string) {
	t.Helper()
	ctx := context.Background()
	st, err := apikeys.OpenStore(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var plaintext string
	if insertKey {
		plaintext, err = apikeys.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		h, err := apikeys.HashSecret(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		pref := apikeys.Prefix12(plaintext)
		_, err = st.InsertKey(ctx, pref, h, "integration", "owner", "integration", rpsLimit, dailyQuota)
		if err != nil {
			t.Fatal(err)
		}
	}

	v, err := apikeys.NewVerifier(st)
	if err != nil {
		t.Fatal(err)
	}
	var rl *redisLimiter
	if redisAddr != "" {
		r, err := newRedisLimiter(redisAddr)
		if err != nil {
			t.Fatal(err)
		}
		rl = r
		t.Cleanup(func() { _ = rl.Close() })
	} else {
		rl, err = newRedisLimiter("")
		if err != nil {
			t.Fatal(err)
		}
	}

	lf := startLastUsedFlusher(st)
	t.Cleanup(func() { lf.Close() })

	f, err := os.Open(testTechnologiesPath(t))
	if err != nil {
		t.Fatal(err)
	}
	wa, err := webanalyze.NewWebAnalyzer(f, nil)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}

	pool := newScanPool(cfg.Workers)
	stReady := &serverState{ready: true}
	log := newLogger("error")
	h := buildHTTPHandler(cfg, st.DB(), wa, pool, stReady, v, rl, lf, log)
	return h, plaintext
}

func TestHealthAndOpenAPI_NoAuth(t *testing.T) {
	cfg := Config{
		Workers:           4,
		DefaultTimeoutMS:  10000,
		MaxTimeoutMS:      30000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	h, _ := newTestHandler(t, cfg, "", true, 20, 200_000)

	t.Run("health", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
	})

	t.Run("openapi json", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/openapi.json", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		v, _ := doc["openapi"].(string)
		if !strings.HasPrefix(v, "3.1") {
			t.Fatalf("expected openapi 3.1.x, got %v", doc["openapi"])
		}
	})

	t.Run("metrics no auth", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
	})
}

func TestAnalyze_Unauthorized(t *testing.T) {
	cfg := Config{
		Workers:           4,
		DefaultTimeoutMS:  10000,
		MaxTimeoutMS:      30000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	h, _ := newTestHandler(t, cfg, "", false, 20, 200_000)

	body := `{"url":"https://example.com"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d %s", rec.Code, rec.Body.String())
	}
	var env map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	errObj := env["error"].(map[string]any)
	if errObj["code"] != CodeUnauthorized {
		t.Fatalf("code %v", errObj["code"])
	}
}

func TestAnalyze_InvalidURL(t *testing.T) {
	cfg := Config{
		Workers:           4,
		DefaultTimeoutMS:  10000,
		MaxTimeoutMS:      30000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	h, key := newTestHandler(t, cfg, "", true, 20, 200_000)

	body := `{"url":"not-a-url"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 got %d %s", rec.Code, rec.Body.String())
	}
	var env map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	errObj := env["error"].(map[string]any)
	if errObj["code"] != CodeInvalidURL {
		t.Fatalf("got %v", errObj["code"])
	}
}

func TestAnalyze_ErrorCodes_Remote(t *testing.T) {
	cfg := Config{
		Workers:           4,
		DefaultTimeoutMS:  5000,
		MaxTimeoutMS:      10000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	h, key := newTestHandler(t, cfg, "", true, 20, 200_000)
	auth := "Bearer " + key

	t.Run("blocked 403", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "no", http.StatusForbidden)
		}))
		defer ts.Close()

		rec := httptest.NewRecorder()
		body := `{"url":"` + ts.URL + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("want 502 got %d %s", rec.Code, rec.Body.String())
		}
		assertCode(t, rec.Body.Bytes(), CodeBlocked403)
	})

	t.Run("empty page", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "   \n\t  ")
		}))
		defer ts.Close()

		rec := httptest.NewRecorder()
		body := `{"url":"` + ts.URL + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("want 502 got %d %s", rec.Code, rec.Body.String())
		}
		assertCode(t, rec.Body.Bytes(), CodeEmptyPage)
	})

	t.Run("captcha", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<html><head></head><body><div class="g-recaptcha"></div></body></html>`)
		}))
		defer ts.Close()

		rec := httptest.NewRecorder()
		body := `{"url":"` + ts.URL + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("want 502 got %d %s", rec.Code, rec.Body.String())
		}
		assertCode(t, rec.Body.Bytes(), CodeBlockedCaptcha)
	})

	t.Run("wordpress html", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<!DOCTYPE html><html><head><link rel="stylesheet" href="/wp-content/themes/foo/style.css"/></head><body>Hi</body></html>`)
		}))
		defer ts.Close()

		rec := httptest.NewRecorder()
		body := `{"url":"` + ts.URL + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200 got %d %s", rec.Code, rec.Body.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if doc["request_id"] == nil || doc["request_id"] == "" {
			t.Fatal("missing request_id")
		}
		techs, ok := doc["technologies"].([]any)
		if !ok || len(techs) == 0 {
			t.Fatalf("expected technologies: %v", doc["technologies"])
		}
	})
}

func TestAnalyze_TargetHostCircuit(t *testing.T) {
	cfg := Config{
		Workers:                  4,
		DefaultTimeoutMS:         5000,
		MaxTimeoutMS:             10000,
		MaxBodyBytes:             1 << 20,
		MaxHTMLBytes:             5_000_000,
		ShutdownDrainSecs:        25,
		TechFile:                 "technologies.json",
		TargetPerHostRPM:         600,
		TargetPerHostBurst:       30,
		TargetHostFailThreshold:  2,
		TargetHostCooldown:       time.Hour,
		TargetHostAcquireTimeout: 5 * time.Second,
		TargetHostLRUSize:        100,
	}
	h, key := newTestHandler(t, cfg, "", true, 20, 200_000)
	auth := "Bearer " + key

	// Connection refused counts as an outbound failure for the circuit breaker.
	body := []byte(`{"url":"http://127.0.0.1:1/"}`)
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("request %d: want 502 got %d %s", i+1, rec.Code, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/analyze", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 circuit got %d %s", rec.Code, rec.Body.String())
	}
	assertCode(t, rec.Body.Bytes(), CodeTargetHostCircuit)
}

func TestRateLimited_RPS(t *testing.T) {
	s := miniredis.RunT(t)
	cfg := Config{
		Workers:           4,
		DefaultTimeoutMS:  5000,
		MaxTimeoutMS:      10000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	h, key := newTestHandler(t, cfg, "redis://"+s.Addr(), true, 1, 1_000_000)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<html><body>x</body></html>`)
	}))
	defer ts.Close()

	body := []byte(`{"url":"` + ts.URL + `"}`)
	do := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		h.ServeHTTP(rec, req)
		return rec
	}
	if do().Code != http.StatusOK {
		t.Fatal("first request should succeed")
	}
	if do().Code != http.StatusOK {
		t.Fatal("second request within burst should succeed")
	}
	rec3 := do()
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 got %d %s", rec3.Code, rec3.Body.String())
	}
	assertCode(t, rec3.Body.Bytes(), CodeRateLimited)
	if rec3.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
}

func assertCode(t *testing.T, raw []byte, want string) {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	errObj := env["error"].(map[string]any)
	if errObj["code"] != want {
		t.Fatalf("want code %s got %v body %s", want, errObj["code"], string(raw))
	}
}

func TestBulkAnalyze_EmptyAndTooLarge(t *testing.T) {
	cfg := Config{
		Workers:           4,
		DefaultTimeoutMS:  10000,
		MaxTimeoutMS:      30000,
		MaxBodyBytes:      1 << 20,
		MaxBulkURLs:       2,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	h, key := newTestHandler(t, cfg, "", true, 20, 200_000)
	auth := "Bearer " + key

	t.Run("empty urls", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze/bulk", strings.NewReader(`{"urls":[]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d %s", rec.Code, rec.Body.String())
		}
		assertCode(t, rec.Body.Bytes(), CodeBatchEmpty)
	})

	t.Run("too many urls", func(t *testing.T) {
		body := `{"urls":["http://a.example","http://b.example","http://c.example"]}`
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze/bulk", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d %s", rec.Code, rec.Body.String())
		}
		assertCode(t, rec.Body.Bytes(), CodeBatchTooLarge)
	})
}

func TestBulkAnalyze_OrderAndMixedResults(t *testing.T) {
	cfg := Config{
		Workers:           4,
		DefaultTimeoutMS:  5000,
		MaxTimeoutMS:      10000,
		MaxBodyBytes:      1 << 20,
		MaxBulkURLs:       50,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
	}
	h, key := newTestHandler(t, cfg, "", true, 20, 200_000)
	auth := "Bearer " + key

	tsOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body>ok</body></html>`)
	}))
	defer tsOK.Close()

	ts403 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer ts403.Close()

	body := `{"urls":["not-a-url","` + tsOK.URL + `","` + ts403.URL + `"]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/analyze/bulk", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 got %d %s", rec.Code, rec.Body.String())
	}

	var doc struct {
		RequestID string `json:"request_id"`
		Results   []struct {
			OK    bool `json:"ok"`
			Data  any  `json:"data"`
			Error *struct {
				Code string `json:"code"`
			} `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Results) != 3 {
		t.Fatalf("want 3 results got %d", len(doc.Results))
	}
	if doc.Results[0].OK || doc.Results[0].Error == nil || doc.Results[0].Error.Code != CodeInvalidURL {
		t.Fatalf("first item: %#v", doc.Results[0])
	}
	if !doc.Results[1].OK || doc.Results[1].Data == nil {
		t.Fatalf("second item: %#v", doc.Results[1])
	}
	if doc.Results[2].OK || doc.Results[2].Error == nil || doc.Results[2].Error.Code != CodeBlocked403 {
		t.Fatalf("third item: %#v", doc.Results[2])
	}
}
