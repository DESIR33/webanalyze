package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

func idempotencyAppliesToPath(path string) bool {
	if !strings.HasPrefix(path, "/v1/") {
		return false
	}
	switch path {
	case "/v1/health", "/v1/ready", "/v1/docs":
		return false
	case "/v1/analyze/async":
		return false
	default:
		if strings.HasPrefix(path, "/v1/openapi") || strings.HasPrefix(path, "/v1/schemas") {
			return false
		}
	}
	return true
}

// bufferedIdemWriter captures status, headers, and body until flushTo so idempotency can patch headers.
type bufferedIdemWriter struct {
	hdr        http.Header
	status     int
	buf        *bytes.Buffer
	captureBuf *bytes.Buffer
	skipCache  bool
}

func newBufferedIdemWriter() *bufferedIdemWriter {
	return &bufferedIdemWriter{
		hdr:        make(http.Header),
		buf:        new(bytes.Buffer),
		captureBuf: new(bytes.Buffer),
	}
}

func (b *bufferedIdemWriter) Header() http.Header {
	return b.hdr
}

func (b *bufferedIdemWriter) WriteHeader(code int) {
	if b.status != 0 {
		return
	}
	b.status = code
}

func (b *bufferedIdemWriter) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	if !b.skipCache && b.captureBuf != nil {
		if b.captureBuf.Len()+len(p) <= idemMaxCachedBody {
			b.captureBuf.Write(p)
		} else {
			b.skipCache = true
			b.captureBuf.Reset()
		}
	}
	return b.buf.Write(p)
}

func (b *bufferedIdemWriter) flushTo(under http.ResponseWriter) error {
	st := b.status
	if st == 0 {
		st = http.StatusOK
	}
	for k, vv := range b.hdr {
		for _, v := range vv {
			under.Header().Add(k, v)
		}
	}
	under.WriteHeader(st)
	_, err := under.Write(b.buf.Bytes())
	return err
}

func idempotencyMiddleware(store *idempotencyStore, maxBodyBytes int64, log *slog.Logger) func(http.Handler) http.Handler {
	if maxBodyBytes < 1 {
		maxBodyBytes = 1 << 20
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w0 http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || !idempotencyAppliesToPath(r.URL.Path) {
				next.ServeHTTP(w0, r)
				return
			}
			if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
				next.ServeHTTP(w0, r)
				return
			}

			idemKey, err := validateIdempotencyKeyHeader(r.Header.Get("Idempotency-Key"))
			if err != nil {
				writeIdempotencyInvalidKey(w0, r)
				return
			}

			kctx := ctxKeyFromContext(r.Context())
			if kctx.KeyID == "" {
				next.ServeHTTP(w0, r)
				return
			}

			maxRead := maxBodyBytes + 1
			body, err := io.ReadAll(io.LimitReader(r.Body, maxRead))
			if err != nil {
				writeInvalidPayload(w0, r)
				return
			}
			_ = r.Body.Close()
			if int64(len(body)) > maxBodyBytes {
				writeTooLarge(w0, requestIDFromCtx(r))
				return
			}

			digest, _, err := canonicalJSONHash(body)
			if err != nil {
				writeInvalidPayload(w0, r)
				return
			}
			bodyHash := idemBodyHashPrefix + digest
			r.Body = io.NopCloser(bytes.NewReader(body))

			if store == nil {
				next.ServeHTTP(w0, r)
				return
			}
			if err := store.ping(r.Context()); err != nil {
				log.Error("idempotency_redis_unavailable", slog.String("err", err.Error()))
				next.ServeHTTP(w0, r)
				return
			}

			redisKey := idemRedisKey(kctx.KeyID, idemKey)
			reqID := requestIDFromCtx(r)
			acquired, lockEntry, err := store.tryAcquire(r.Context(), redisKey, bodyHash, reqID)
			if err != nil {
				log.Error("idempotency_acquire", slog.String("err", err.Error()))
				next.ServeHTTP(w0, r)
				return
			}

			if !acquired {
				handleIdempotencyExisting(w0, r, idemKey, bodyHash, lockEntry, log)
				return
			}

			firstSeen, _ := time.Parse(time.RFC3339Nano, lockEntry.FirstSeenAt)
			if firstSeen.IsZero() {
				firstSeen, _ = time.Parse(time.RFC3339, lockEntry.FirstSeenAt)
			}
			if firstSeen.IsZero() {
				firstSeen = time.Now().UTC()
			}

			bufW := newBufferedIdemWriter()
			setIdempotencyCoreHeaders(bufW.hdr, idemKey, false, firstSeen, "")
			patchIdempotencyStoredHeaders(bufW.hdr, true, "")

			ww := middleware.NewWrapResponseWriter(bufW, r.ProtoMajor)
			next.ServeHTTP(ww, r)

			finalizeIdempotentRequest(r.Context(), store, redisKey, reqID, lockEntry, bodyHash, bufW, ww, log)
			_ = bufW.flushTo(w0)
		})
	}
}

func requestIDFromCtx(r *http.Request) string {
	if id, ok := r.Context().Value(ctxRequestID).(string); ok && id != "" {
		return id
	}
	return strings.TrimSpace(r.Header.Get("X-Request-ID"))
}

func writeIdempotencyInvalidKey(w http.ResponseWriter, r *http.Request) {
	waIdempotencyRequests.WithLabelValues("invalid_key").Inc()
	writeJSONError(w, http.StatusBadRequest, CodeInvalidIdempotencyKey, "Idempotency-Key must be 1–255 ASCII characters without whitespace or control characters", false, requestIDFromCtx(r))
}

func writeInvalidPayload(w http.ResponseWriter, r *http.Request) {
	writeJSONError(w, http.StatusBadRequest, CodeInvalidPayload, "Request body must be valid JSON", false, requestIDFromCtx(r))
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string, retry bool, reqID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":       code,
			"message":    msg,
			"retryable":  retry,
			"request_id": reqID,
		},
	})
}

func setIdempotencyCoreHeaders(hdr http.Header, idemKey string, replayed bool, firstSeen time.Time, origReqID string) {
	hdr.Set("Idempotency-Key", idemKey)
	hdr.Set("X-Idempotency-Replayed", strconv.FormatBool(replayed))
	hdr.Set("X-Idempotency-First-Seen-At", firstSeen.UTC().Format(time.RFC3339Nano))
	if origReqID != "" {
		hdr.Set("X-Idempotency-Original-Request-Id", origReqID)
	} else {
		hdr.Del("X-Idempotency-Original-Request-Id")
	}
}

func patchIdempotencyStoredHeaders(hdr http.Header, stored bool, reason string) {
	hdr.Set("X-Idempotency-Stored", strconv.FormatBool(stored))
	if !stored && reason != "" {
		hdr.Set("X-Idempotency-Stored-Reason", reason)
	} else {
		hdr.Del("X-Idempotency-Stored-Reason")
	}
}

func handleIdempotencyExisting(w http.ResponseWriter, r *http.Request, idemKey, bodyHash string, existing idemRedisEntry, log *slog.Logger) {
	reqID := requestIDFromCtx(r)
	firstSeen, _ := time.Parse(time.RFC3339Nano, existing.FirstSeenAt)
	if firstSeen.IsZero() {
		firstSeen, _ = time.Parse(time.RFC3339, existing.FirstSeenAt)
	}
	if firstSeen.IsZero() {
		firstSeen = time.Now().UTC()
	}

	switch idemEntryState(existing.State) {
	case idemStateCompleted:
		if existing.BodyHash != bodyHash {
			waIdempotencyRequests.WithLabelValues("conflict").Inc()
			setIdempotencyCoreHeaders(w.Header(), idemKey, false, firstSeen, "")
			patchIdempotencyStoredHeaders(w.Header(), false, "")
			writeJSONError(w, http.StatusUnprocessableEntity, CodeIdempotencyKeyConflict, "Idempotency-Key was reused with a different request body", false, reqID)
			return
		}
		if existing.Response == nil {
			log.Error("idempotency_completed_missing_response", slog.String("key", idemKey))
			waIdempotencyRequests.WithLabelValues("conflict").Inc()
			setIdempotencyCoreHeaders(w.Header(), idemKey, false, firstSeen, "")
			patchIdempotencyStoredHeaders(w.Header(), false, "")
			writeJSONError(w, http.StatusInternalServerError, CodeInternal, "Idempotency state corrupted", false, reqID)
			return
		}
		waIdempotencyRequests.WithLabelValues("replay").Inc()
		if existing.DurationMS > 0 {
			waIdempotencyReplaySavingsSeconds.Observe(float64(existing.DurationMS) / 1000)
		}
		idemReplayAudit(log, r, idemKey, existing.RequestID, reqID, ctxKeyFromContext(r.Context()).Owner)
		setIdempotencyCoreHeaders(w.Header(), idemKey, true, firstSeen, existing.RequestID)
		patchIdempotencyStoredHeaders(w.Header(), true, "")
		_ = writeCachedResponse(w, *existing.Response)
		return

	case idemStateInProgress:
		if existing.BodyHash != bodyHash {
			waIdempotencyRequests.WithLabelValues("conflict").Inc()
			setIdempotencyCoreHeaders(w.Header(), idemKey, false, firstSeen, "")
			patchIdempotencyStoredHeaders(w.Header(), false, "")
			writeJSONError(w, http.StatusUnprocessableEntity, CodeIdempotencyKeyConflict, "Idempotency-Key was reused with a different request body", false, reqID)
			return
		}
		waIdempotencyRequests.WithLabelValues("in_progress").Inc()
		setIdempotencyCoreHeaders(w.Header(), idemKey, false, firstSeen, "")
		patchIdempotencyStoredHeaders(w.Header(), false, "")
		w.Header().Set("Retry-After", "5")
		writeJSONError(w, http.StatusConflict, CodeIdempotencyInProgress, "Original request with this Idempotency-Key is still in progress", true, reqID)
		return

	default:
		waIdempotencyRequests.WithLabelValues("fresh").Inc()
		setIdempotencyCoreHeaders(w.Header(), idemKey, false, firstSeen, "")
		patchIdempotencyStoredHeaders(w.Header(), false, "unknown_state")
		writeJSONError(w, http.StatusInternalServerError, CodeInternal, "Idempotency state invalid", false, reqID)
	}
}

func idemReplayAudit(log *slog.Logger, r *http.Request, idemKey, originalReqID, currentReqID, owner string) {
	if log == nil {
		return
	}
	log.Info("idempotency_replay",
		slog.String("event", "idempotency_replay"),
		slog.String("idempotency_key", idemKey),
		slog.String("original_request_id", originalReqID),
		slog.String("request_id", currentReqID),
		slog.String("route", r.Method+" "+r.URL.Path),
		slog.String("owner", owner),
	)
}

func parseDurationMSFromSuccessJSON(body []byte) int64 {
	var doc struct {
		DurationMS int64 `json:"duration_ms"`
	}
	if json.Unmarshal(body, &doc) == nil {
		return doc.DurationMS
	}
	return 0
}

func finalizeIdempotentRequest(ctx context.Context, store *idempotencyStore, redisKey, reqID string, lockEntry idemRedisEntry, bodyHash string, bufW *bufferedIdemWriter, ww middleware.WrapResponseWriter, log *slog.Logger) {
	status := ww.Status()
	if status == 0 {
		status = http.StatusOK
	}
	body := bufW.captureBuf.Bytes()
	cacheable := !bufW.skipCache && idempotencyResponseCacheable(status, body)

	if status >= 500 {
		waIdempotencyRequests.WithLabelValues("fresh").Inc()
		if err := store.abandonIfOwner(ctx, redisKey, reqID); err != nil {
			log.Error("idempotency_abandon", slog.String("err", err.Error()))
		}
		patchIdempotencyStoredHeaders(bufW.hdr, false, "server_error")
		return
	}

	if !cacheable {
		waIdempotencyRequests.WithLabelValues("skipped_too_large").Inc()
		if err := store.abandonIfOwner(ctx, redisKey, reqID); err != nil {
			log.Error("idempotency_abandon", slog.String("err", err.Error()))
		}
		reason := "not_cacheable"
		if bufW.skipCache && status >= 200 && status < 300 {
			reason = "response_too_large"
		}
		patchIdempotencyStoredHeaders(bufW.hdr, false, reason)
		return
	}

	waIdempotencyRequests.WithLabelValues("fresh").Inc()

	durationMS := parseDurationMSFromSuccessJSON(body)
	completed := idemRedisEntry{
		State:       string(idemStateCompleted),
		BodyHash:    bodyHash,
		FirstSeenAt: lockEntry.FirstSeenAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
		RequestID:   reqID,
		DurationMS:  durationMS,
		Response:    idemptr(idemResponseFromHTTP(status, bufW.hdr.Clone(), body)),
	}
	if err := store.completeIfOwner(ctx, redisKey, reqID, completed); err != nil {
		log.Error("idempotency_complete", slog.String("err", err.Error()))
	}
	patchIdempotencyStoredHeaders(bufW.hdr, true, "")
}

func idemptr[T any](v T) *T { return &v }
