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

	"github.com/rverton/webanalyze"
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

func newTestHandler(t *testing.T, cfg Config, keysEnv string) http.Handler {
	t.Helper()
	ctx := context.Background()
	db, err := openKeysDB(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := migrateKeys(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := seedAPIKeys(ctx, db, keysEnv); err != nil {
		t.Fatal(err)
	}

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
	st := &serverState{ready: true}
	log := newLogger("error")
	return buildHTTPHandler(cfg, db, wa, pool, st, log)
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
	h := newTestHandler(t, cfg, "t:testsecret")

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
	h := newTestHandler(t, cfg, "kid:secret")

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
	h := newTestHandler(t, cfg, "kid:secret")

	body := `{"url":"not-a-url"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer kid:secret")
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
	h := newTestHandler(t, cfg, "kid:secret")
	auth := "Bearer kid:secret"

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

func TestRateLimited(t *testing.T) {
	cfg := Config{
		Workers:           4,
		DefaultTimeoutMS:  5000,
		MaxTimeoutMS:      10000,
		MaxBodyBytes:      1 << 20,
		MaxHTMLBytes:      5_000_000,
		ShutdownDrainSecs: 25,
		TechFile:          "technologies.json",
		RateLimitPerMin:   1,
	}
	h := newTestHandler(t, cfg, "kid:secret")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<html><body>x</body></html>`)
	}))
	defer ts.Close()

	body := []byte(`{"url":"` + ts.URL + `"}`)
	do := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/analyze", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer kid:secret")
		h.ServeHTTP(rec, req)
		return rec
	}
	if do().Code != http.StatusOK {
		t.Fatal("first request should succeed")
	}
	rec2 := do()
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 got %d %s", rec2.Code, rec2.Body.String())
	}
	assertCode(t, rec2.Body.Bytes(), CodeRateLimited)
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
