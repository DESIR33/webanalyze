package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/rverton/webanalyze"
	"github.com/rverton/webanalyze/internal/asyncjobs"
)

type asyncRuntime struct {
	cfg    Config
	js     *asyncjobs.Store
	wa     *webanalyze.WebAnalyzer
	pool   *scanPool
	log    *slog.Logger
	cancel context.CancelFunc

	workerWG sync.WaitGroup
}

func startAsyncRuntime(parent context.Context, cfg Config, js *asyncjobs.Store, wa *webanalyze.WebAnalyzer, pool *scanPool, log *slog.Logger) *asyncRuntime {
	if js == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(parent)
	ar := &asyncRuntime{cfg: cfg, js: js, wa: wa, pool: pool, log: log, cancel: cancel}

	for i := 0; i < cfg.AsyncWorkers; i++ {
		ar.workerWG.Add(1)
		go ar.scanWorker(ctx, "worker-"+strconv.Itoa(i))
	}
	go ar.leaseSweeper(ctx)
	go ar.retentionCleaner(ctx)
	go ar.webhookDispatcher(ctx)
	go ar.queueDepthPoller(ctx)
	return ar
}

func (ar *asyncRuntime) Stop() {
	ar.cancel()
	ar.workerWG.Wait()
}

func (ar *asyncRuntime) scanWorker(ctx context.Context, id string) {
	defer ar.workerWG.Done()
	lease := time.Duration(ar.cfg.AsyncLeaseSeconds) * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		job, err := ar.js.TryLeaseNextJob(ctx, id, lease, time.Now().UTC())
		if err != nil {
			ar.log.Error("async_lease", slog.String("err", err.Error()))
			time.Sleep(time.Second)
			continue
		}
		if job == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		ar.runOneScan(ctx, job)
	}
}

func (ar *asyncRuntime) runOneScan(ctx context.Context, job *asyncjobs.JobRow) {
	t0 := time.Now()
	ar.log.Info("async_lease",
		slog.String("event", "async_lease"),
		slog.String("job_id", job.ID),
		slog.String("api_key_id", job.APIKeyID),
	)
	var input struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(job.InputJSON, &input); err != nil {
		ar.failTerminal(ctx, job.ID, "INVALID_PAYLOAD", "invalid job input JSON", false, nil)
		return
	}
	rawURL := strings.TrimSpace(input.URL)
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		ar.failTerminal(ctx, job.ID, CodeInvalidURL, "url must be an absolute http or https URL", false, nil)
		return
	}
	var opts AnalyzeOptions
	_ = json.Unmarshal(job.OptionsJSON, &opts)

	timeoutMS := ar.cfg.DefaultTimeoutMS
	if opts.TimeoutMS > 0 {
		timeoutMS = opts.TimeoutMS
	}
	if timeoutMS > ar.cfg.MaxTimeoutMS {
		timeoutMS = ar.cfg.MaxTimeoutMS
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

	wjob := webanalyze.NewOnlineJob(u.String(), "", nil, opts.CrawlDepth, includeSub, follow)
	wjob.MaxHTMLBytes = ar.cfg.MaxHTMLBytes
	wjob.UserAgent = ua
	client := buildHTTPClient(timeout, follow, u.String(), ar.cfg)

	acquireCtx, cancel := context.WithTimeout(ctx, timeout+2*time.Second)
	defer cancel()
	if err := ar.pool.acquire(acquireCtx); err != nil {
		_ = ar.js.RequeueRetryable(ctx, job.ID, time.Second+time.Duration(rand.Intn(500))*time.Millisecond,
			mustErrJSON(CodeInternal, "worker pool unavailable", true), time.Now().UTC())
		return
	}
	defer ar.pool.release()

	res, _ := ar.wa.ProcessWithClient(wjob, client)
	waAsyncRunSeconds.Observe(time.Since(t0).Seconds())

	if res.Error != nil {
		te := classifyScanError(job.ID, res.Error)
		errB := mustErrPayload(te.Payload.Code, te.Payload.Message, te.Payload.Retryable)
		if te.Payload.Retryable && job.Attempts < 3 {
			delay := scanRetryBackoff(job.Attempts)
			_ = ar.js.RequeueRetryable(ctx, job.ID, delay, errB, time.Now().UTC())
			ar.log.Info("async_requeue",
				slog.String("event", "async_requeue"),
				slog.String("job_id", job.ID),
				slog.Int("attempts", job.Attempts),
				slog.String("code", te.Payload.Code),
			)
			return
		}
		_ = ar.js.MarkJobFailedTerminal(ctx, job.ID, errB, nil, time.Now().UTC())
		waAsyncStatusTotal.WithLabelValues("failed").Inc()
		ar.log.Info("async_complete",
			slog.String("event", "async_complete"),
			slog.String("job_id", job.ID),
			slog.String("status", "failed"))
		return
	}

	final := res.FinalURL
	if final == "" {
		final = res.Host
	}
	payload := AnalyzeSuccessResponse{
		RequestID:    job.ID,
		InputURL:     rawURL,
		FinalURL:     final,
		ScannedAt:    time.Now().UTC().Truncate(time.Millisecond),
		DurationMS:   res.Duration.Milliseconds(),
		Technologies: mapMatchesToTech(ar.wa, res),
		Stats: AnalyzeStats{
			FetchStatus:           res.FetchStatus,
			HTMLBytes:             res.HTMLBytes,
			FingerprintsEvaluated: res.FingerprintsEvaluated,
		},
	}
	resBytes, _ := json.Marshal(payload)
	now := time.Now().UTC()
	if err := ar.js.MarkJobSucceeded(ctx, job.ID, resBytes, now); err != nil {
		ar.log.Error("async_mark_succeeded", slog.String("err", err.Error()))
		return
	}
	waAsyncStatusTotal.WithLabelValues("succeeded").Inc()
	ar.log.Info("async_complete",
		slog.String("event", "async_complete"),
		slog.String("job_id", job.ID),
		slog.String("status", "succeeded"))
}

func scanRetryBackoff(attempts int) time.Duration {
	base := time.Second
	switch attempts {
	case 1:
		base = 2 * time.Second
	case 2:
		base = 5 * time.Second
	default:
		base = 10 * time.Second
	}
	j := time.Duration(rand.Intn(int(base)))
	return base + j
}

func (ar *asyncRuntime) failTerminal(ctx context.Context, jobID, code, msg string, retryable bool, resultJSON []byte) {
	b := mustErrJSON(code, msg, retryable)
	_ = ar.js.MarkJobFailedTerminal(ctx, jobID, b, resultJSON, time.Now().UTC())
	waAsyncStatusTotal.WithLabelValues("failed").Inc()
}

func mustErrJSON(code, msg string, retryable bool) []byte {
	b, _ := json.Marshal(map[string]any{
		"code": code, "message": msg, "retryable": retryable,
	})
	return b
}

func mustErrPayload(code, msg string, retryable bool) []byte {
	return mustErrJSON(code, msg, retryable)
}

func (ar *asyncRuntime) leaseSweeper(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := ar.js.SweepExpiredLeases(ctx, time.Now().UTC())
			if err != nil {
				ar.log.Error("async_lease_sweep", slog.String("err", err.Error()))
				continue
			}
			if n > 0 {
				ar.log.Info("async_lease_sweep", slog.Int64("recovered", n))
			}
		}
	}
}

func (ar *asyncRuntime) retentionCleaner(ctx context.Context) {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := ar.js.DeleteExpiredJobs(ctx, time.Now().UTC())
			if err != nil {
				ar.log.Error("async_retention", slog.String("err", err.Error()))
				continue
			}
			if n > 0 {
				ar.log.Info("async_retention", slog.Int64("deleted", n))
			}
		}
	}
}

func (ar *asyncRuntime) queueDepthPoller(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := ar.js.CountQueued(ctx)
			if err != nil {
				continue
			}
			waAsyncQueueDepth.Set(float64(n))
		}
	}
}

func (ar *asyncRuntime) webhookDispatcher(ctx context.Context) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ids, err := ar.js.PickDueDeliveries(ctx, time.Now().UTC(), 32)
			if err != nil || len(ids) == 0 {
				continue
			}
			for _, id := range ids {
				ar.deliverWebhook(ctx, id)
			}
		}
	}
}

func (ar *asyncRuntime) deliverWebhook(ctx context.Context, jobID string) {
	job, err := ar.js.GetJob(ctx, jobID)
	if job == nil || !job.CallbackURL.Valid || job.CallbackURL.String == "" || !job.SigningSecretID.Valid {
		return
	}
	if job.CancelledNotDeliverable {
		_ = ar.js.MarkWebhookDelivered(ctx, jobID, time.Now().UTC())
		return
	}
	plain, err := ar.js.WebhookSigningPlaintext(ctx, job.APIKeyID, job.SigningSecretID.String, ar.cfg.WebhookRotationOverlap)
	if err != nil {
		ar.log.Error("webhook_signing_secret", slog.String("job_id", jobID), slog.String("err", err.Error()))
		return
	}
	evtID := "evt_" + ulid.Make().String()
	jobView := jobRowToAPIView(job, ar.cfg)
	typ := "job.succeeded"
	if job.Status == asyncjobs.StatusFailed {
		typ = "job.failed"
	}
	bodyObj := map[string]any{
		"id":         evtID,
		"type":       typ,
		"created_at": time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
		"job":        jobView,
	}
	body, _ := json.Marshal(bodyObj)
	ts := time.Now().Unix()
	sig := asyncjobs.WebhookSignatureHeader([]byte(plain), ts, body)
	attempt := job.DeliveryAttempts + 1

	pin := &asyncjobs.CallbackPin{
		CallbackURL: job.CallbackURL.String,
		ResolvedIP:  job.CallbackResolvedIP.String,
		HostHeader:  job.CallbackHostHeader.String,
	}
	code, errStr, ok := postWebhook(ctx, pin, body, evtID, strconv.FormatInt(ts, 10), sig, strconv.Itoa(attempt),
		time.Duration(ar.cfg.WebhookTimeoutSeconds)*time.Second)

	ar.log.Info("async_deliver_attempt",
		slog.String("event", "async_deliver_attempt"),
		slog.String("job_id", jobID),
		slog.Int("attempt", attempt),
		slog.Int("http_status", code),
		slog.String("err", errStr),
	)

	label := webhookOutcomeLabel(code, errStr)
	waWebhookAttemptsTotal.WithLabelValues(label).Inc()

	if ok {
		_ = ar.js.BumpDeliveryAttempt(ctx, jobID, attempt, code, "", sql.NullTime{}, time.Now().UTC())
		_ = ar.js.MarkWebhookDelivered(ctx, jobID, time.Now().UTC())
		waWebhookDeliveryAttemptsToSuccess.Observe(float64(attempt))
		return
	}

	if code == http.StatusGone {
		_ = ar.js.BumpDeliveryAttempt(ctx, jobID, attempt, code, "gone", sql.NullTime{}, time.Now().UTC())
		_ = ar.js.MarkWebhookExhausted(ctx, jobID, time.Now().UTC())
		// Owner label unavailable in delivery goroutine without extra DB read; use reason.
		waWebhookDeadLetteredTotal.WithLabelValues("gone").Inc()
		return
	}

	nextAt, exhausted := webhookScheduleNext(attempt, time.Now().UTC())
	_ = ar.js.BumpDeliveryAttempt(ctx, jobID, attempt, code, errStr, nextAt, time.Now().UTC())
	if exhausted {
		_ = ar.js.MarkWebhookExhausted(ctx, jobID, time.Now().UTC())
		waWebhookDeadLetteredTotal.WithLabelValues("exhausted").Inc()
	}
}

func webhookOutcomeLabel(code int, errStr string) string {
	if errStr == "timeout" {
		return "timeout"
	}
	if errStr == "network" {
		return "network"
	}
	if code == 0 {
		return "network"
	}
	if code >= 200 && code < 300 {
		return "2xx"
	}
	if code >= 500 {
		return "5xx"
	}
	return "4xx"
}

// Nominal delay (seconds) before the next attempt after attempt `justCompleted` failed.
// Attempt 1 is immediate; after attempt 1 fails wait up to 30s; ... after attempt 6 fails, exhausted.
func webhookScheduleNext(justCompleted int, now time.Time) (sql.NullTime, bool) {
	if justCompleted >= 6 {
		return sql.NullTime{}, true
	}
	delays := []int{0, 30, 120, 600, 3600, 21600}
	if justCompleted < 0 || justCompleted >= len(delays) {
		return sql.NullTime{}, true
	}
	sec := delays[justCompleted]
	if sec <= 0 {
		return sql.NullTime{Time: now, Valid: true}, false
	}
	j := rand.Intn(sec + 1)
	return sql.NullTime{Time: now.Add(time.Duration(j) * time.Second), Valid: true}, false
}

func postWebhook(ctx context.Context, pin *asyncjobs.CallbackPin, body []byte, evtID, ts, sig, attempt string, timeout time.Duration) (httpCode int, errMsg string, ok bool) {
	u, err := url.Parse(pin.CallbackURL)
	if err != nil {
		return 0, "invalid_callback", false
	}
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(pin.ResolvedIP, port)

	dialer := &net.Dialer{Timeout: timeout}
	tr := defaultHTTPTransport().Clone()
	tr.DialContext = func(c context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(c, network, addr)
	}
	if strings.EqualFold(u.Scheme, "https") {
		tr.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: u.Hostname(),
		}
	} else {
		tr.TLSClientConfig = nil
	}
	client := &http.Client{Transport: tr, Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pin.CallbackURL, strings.NewReader(string(body)))
	if err != nil {
		return 0, "build_request", false
	}
	req.Host = pin.HostHeader
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Webanalyze-Event-Id", evtID)
	req.Header.Set("Webanalyze-Timestamp", ts)
	req.Header.Set("Webanalyze-Signature", sig)
	req.Header.Set("Webanalyze-Delivery-Attempt", attempt)

	res, err := client.Do(req)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return 0, "timeout", false
		}
		if ctx.Err() != nil {
			return 0, "canceled", false
		}
		return 0, "network", false
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return res.StatusCode, "", true
	}
	if res.StatusCode == http.StatusGone {
		return res.StatusCode, "gone", false
	}
	return res.StatusCode, "http", false
}
