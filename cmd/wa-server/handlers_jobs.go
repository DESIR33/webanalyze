package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/oklog/ulid/v2"
	"github.com/rverton/webanalyze/internal/apikeys"
	"github.com/rverton/webanalyze/internal/asyncjobs"
)

const jobIDPrefix = "job_"

type AsyncCallbackBody struct {
	URL             string `json:"url" format:"uri"`
	SigningSecretID string `json:"signing_secret_id"`
}

type AsyncAnalyzeBody struct {
	URL      string             `json:"url" format:"uri"`
	Options  AnalyzeOptions     `json:"options,omitempty"`
	Callback *AsyncCallbackBody `json:"callback,omitempty"`
	Metadata map[string]any     `json:"metadata,omitempty"`
}

type AsyncAcceptedResponse struct {
	JobID                      string `json:"job_id"`
	Status                     string `json:"status"`
	SubmittedAt                string `json:"submitted_at"`
	PollURL                    string `json:"poll_url"`
	EstimatedCompletionSeconds int    `json:"estimated_completion_seconds"`
}

func registerAsyncRoutes(api huma.API, cfg Config, js *asyncjobs.Store, log *slog.Logger) {
	if js == nil {
		return
	}

	type AsyncIn struct {
		RequestID       string `header:"X-Request-ID"`
		IdempotencyKey  string `header:"Idempotency-Key"`
		Body            AsyncAnalyzeBody
	}
	type AsyncOut struct {
		Status int
		Body   AsyncAcceptedResponse
	}

	huma.Register(api, huma.Operation{
		OperationID:   "analyzeAsync",
		Method:        http.MethodPost,
		Path:          "/v1/analyze/async",
		DefaultStatus: http.StatusAccepted,
		Summary:       "Queue asynchronous URL analysis (webhook and/or poll)",
		Tags:          []string{"Jobs"},
		MaxBodyBytes:  cfg.MaxBodyBytes,
		Security:      []map[string][]string{{"bearerAuth": {}}},
	}, func(ctx context.Context, in *AsyncIn) (*AsyncOut, error) {
		reqID := strings.TrimSpace(in.RequestID)
		if reqID == "" {
			reqID = newRequestID()
		}
		kc := ctxKeyFromContext(ctx)

		rawURL := strings.TrimSpace(in.Body.URL)
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, errTyped(400, CodeInvalidURL, "url must be an absolute http or https URL", false, reqID)
		}

		optBytes, _ := json.Marshal(in.Body.Options)
		inBytes, _, err := asyncjobs.MarshalJobInputOptions(rawURL, optBytes)
		if err != nil {
			return nil, errTyped(400, CodeInvalidPayload, "invalid options", false, reqID)
		}

		rawBody, err := json.Marshal(in.Body)
		if err != nil {
			return nil, errTyped(400, CodeInvalidPayload, "invalid body", false, reqID)
		}
		canonHash, _, err := canonicalJSONHash(rawBody)
		if err != nil {
			return nil, errTyped(400, CodeInvalidPayload, "invalid json for idempotency", false, reqID)
		}

		idem := strings.TrimSpace(in.IdempotencyKey)
		if idem != "" {
			prevID, submitted, ierr := js.FindJobByIdempotency(ctx, kc.KeyID, idem)
			if ierr == nil && prevID != "" {
				existing, e2 := js.GetJob(ctx, prevID)
				if e2 != nil {
					return nil, errTyped(500, CodeInternal, "database error", true, reqID)
				}
				if !existing.IdempotencyBodyHash.Valid || existing.IdempotencyBodyHash.String != canonHash {
					return nil, errTyped(422, CodeIdempotencyKeyConflict, "Idempotency-Key was reused with a different request body", false, reqID)
				}
				return &AsyncOut{
					Status: http.StatusAccepted,
					Body: AsyncAcceptedResponse{
						JobID:                      prevID,
						Status:                     existing.Status,
						SubmittedAt:                submitted.UTC().Truncate(time.Second).Format(time.RFC3339),
						PollURL:                    "/v1/jobs/" + prevID,
						EstimatedCompletionSeconds: 8,
					},
				}, nil
			}
			if ierr != nil && !errors.Is(ierr, sql.ErrNoRows) {
				return nil, errTyped(500, CodeInternal, "database error", true, reqID)
			}
		}

		var metaBytes []byte
		if len(in.Body.Metadata) > 0 {
			metaBytes, err = json.Marshal(in.Body.Metadata)
			if err != nil {
				return nil, errTyped(400, CodeInvalidPayload, "invalid metadata", false, reqID)
			}
		}

		jobID := jobIDPrefix + ulid.Make().String()

		row := asyncjobs.JobRow{
			ID:          jobID,
			APIKeyID:    kc.KeyID,
			Status:      asyncjobs.StatusQueued,
			InputJSON:   inBytes,
			OptionsJSON: optBytes,
			Attempts:    0,
		}
		if len(metaBytes) > 0 {
			row.MetadataJSON = metaBytes
		}

		if in.Body.Callback != nil && (strings.TrimSpace(in.Body.Callback.URL) != "" || strings.TrimSpace(in.Body.Callback.SigningSecretID) != "") {
			cbURL := strings.TrimSpace(in.Body.Callback.URL)
			secID := strings.TrimSpace(in.Body.Callback.SigningSecretID)
			if cbURL == "" || secID == "" {
				return nil, errTyped(400, CodeInvalidPayload, "callback requires url and signing_secret_id", false, reqID)
			}
			pin, err := asyncjobs.ValidateAndPinCallbackURL(cbURL, asyncjobs.CallbackValidationConfig{
				AllowPlaintextHTTP:  cfg.AllowPlaintextCallbacks,
				AllowInternalTarget: cfg.AllowInternalCallbacks,
				HostSuffixAllowlist: cfg.CallbackHostAllowlist,
			})
			if err != nil {
				return nil, errTyped(400, CodeInvalidCallbackURL, err.Error(), false, reqID)
			}
			_, err = js.WebhookSigningPlaintext(ctx, kc.KeyID, secID, 3650*24*time.Hour)
			if err != nil {
				if errors.Is(err, asyncjobs.ErrNotFound) {
					return nil, errTyped(400, CodeUnknownSigningSecret, "signing_secret_id not found or revoked", false, reqID)
				}
				return nil, errTyped(500, CodeInternal, "could not verify signing secret", false, reqID)
			}
			row.CallbackURL = sql.NullString{String: pin.CallbackURL, Valid: true}
			row.CallbackResolvedIP = sql.NullString{String: pin.ResolvedIP, Valid: true}
			row.CallbackHostHeader = sql.NullString{String: pin.HostHeader, Valid: true}
			row.SigningSecretID = sql.NullString{String: secID, Valid: true}
			row.DeliveryStatus = asyncjobs.DeliveryPending
		} else {
			row.DeliveryStatus = asyncjobs.DeliveryNA
		}

		if idem != "" {
			row.IdempotencyKey = sql.NullString{String: idem, Valid: true}
			row.IdempotencyBodyHash = sql.NullString{String: canonHash, Valid: true}
		}

		if err := js.InsertJob(ctx, row); err != nil {
			log.Error("async_insert_job", slog.String("err", err.Error()))
			return nil, errTyped(500, CodeInternal, "could not enqueue job", true, reqID)
		}

		waAsyncSubmittedTotal.WithLabelValues(kc.Owner).Inc()
		log.Info("async_submit",
			slog.String("event", "async_submit"),
			slog.String("job_id", jobID),
			slog.String("api_key_id", kc.KeyID),
			slog.String("request_id", reqID),
		)

		now := time.Now().UTC().Truncate(time.Second)
		return &AsyncOut{
			Status: http.StatusAccepted,
			Body: AsyncAcceptedResponse{
				JobID:                      jobID,
				Status:                     asyncjobs.StatusQueued,
				SubmittedAt:                now.Format(time.RFC3339),
				PollURL:                    "/v1/jobs/" + jobID,
				EstimatedCompletionSeconds: 8,
			},
		}, nil
	})

	type GetJobIn struct {
		ID string `path:"id"`
	}
	type GetJobOut struct {
		Body JobStatusPayload
	}
	huma.Register(api, huma.Operation{
		OperationID: "getJob",
		Method:      http.MethodGet,
		Path:        "/v1/jobs/{id}",
		Summary:     "Get job status and result",
		Tags:        []string{"Jobs"},
		Security:    []map[string][]string{{"bearerAuth": {}}},
	}, func(ctx context.Context, in *GetJobIn) (*GetJobOut, error) {
		reqID := newRequestID()
		kc := ctxKeyFromContext(ctx)
		j, err := js.GetJobWithinRetention(ctx, in.ID, time.Now().UTC())
		if err != nil {
			if errors.Is(err, asyncjobs.ErrNotFound) {
				return nil, errTyped(404, CodeJobNotFound, "job not found or expired", false, reqID)
			}
			return nil, errTyped(500, CodeInternal, "database error", true, reqID)
		}
		if j.APIKeyID != kc.KeyID {
			return nil, errTyped(403, CodeJobNotOwned, "job belongs to another API key", false, reqID)
		}
		return &GetJobOut{Body: jobRowToAPIView(j, cfg)}, nil
	})

	type DelJobIn struct {
		ID string `path:"id"`
	}
	huma.Register(api, huma.Operation{
		OperationID: "cancelJob",
		Method:      http.MethodDelete,
		Path:        "/v1/jobs/{id}",
		Summary:     "Cancel a queued job",
		Tags:        []string{"Jobs"},
		Security:    []map[string][]string{{"bearerAuth": {}}},
	}, func(ctx context.Context, in *DelJobIn) (*struct{}, error) {
		reqID := newRequestID()
		kc := ctxKeyFromContext(ctx)
		j, err := js.GetJobWithinRetention(ctx, in.ID, time.Now().UTC())
		if err != nil {
			if errors.Is(err, asyncjobs.ErrNotFound) {
				return nil, errTyped(404, CodeJobNotFound, "job not found or expired", false, reqID)
			}
			return nil, errTyped(500, CodeInternal, "database error", true, reqID)
		}
		if j.APIKeyID != kc.KeyID {
			return nil, errTyped(403, CodeJobNotOwned, "job belongs to another API key", false, reqID)
		}
		term, st, err := js.JobIsTerminal(ctx, in.ID)
		if err != nil {
			return nil, errTyped(500, CodeInternal, "database error", true, reqID)
		}
		if term {
			return nil, errTyped(409, CodeJobTerminal, "job is already in terminal state: "+st, false, reqID)
		}
		if j.Status == asyncjobs.StatusQueued {
			if err := js.MarkCancelledQueued(ctx, in.ID, time.Now().UTC()); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil, errTyped(409, CodeJobTerminal, "job could not be cancelled", false, reqID)
				}
				return nil, errTyped(500, CodeInternal, "database error", true, reqID)
			}
			waAsyncStatusTotal.WithLabelValues("cancelled").Inc()
			log.Info("async_cancel", slog.String("event", "async_cancel"), slog.String("job_id", in.ID))
			return &struct{}{}, nil
		}
		if j.Status == asyncjobs.StatusRunning {
			_ = js.MarkCancelRunningUndeliverable(ctx, in.ID)
			log.Info("async_cancel_running", slog.String("event", "async_cancel_running"), slog.String("job_id", in.ID))
			return &struct{}{}, nil
		}
		return nil, errTyped(409, CodeJobTerminal, "job is not cancellable in current state", false, reqID)
	})

	type ListJobsIn struct {
		Status string `query:"status"`
		Limit  int    `query:"limit" minimum:"1" maximum:"500"`
	}
	type ListJobsOut struct {
		Body struct {
			Jobs []JobStatusPayload `json:"jobs"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "listJobs",
		Method:      http.MethodGet,
		Path:        "/v1/jobs",
		Summary:     "List jobs (admin: dead_lettered)",
		Tags:        []string{"Jobs"},
		Security:    []map[string][]string{{"bearerAuth": {}}},
	}, func(ctx context.Context, in *ListJobsIn) (*ListJobsOut, error) {
		reqID := newRequestID()
		kc := ctxKeyFromContext(ctx)
		if !isJobAdmin(kc, cfg) {
			return nil, errTyped(403, CodeUnauthorized, "admin listing not permitted for this key", false, reqID)
		}
		if strings.TrimSpace(in.Status) != asyncjobs.StatusDeadLettered {
			return nil, errTyped(400, CodeInvalidPayload, "only status=dead_lettered is supported", false, reqID)
		}
		limit := in.Limit
		if limit == 0 {
			limit = 50
		}
		rows, err := js.ListDeadLetteredAdmin(ctx, "", limit)
		if err != nil {
			return nil, errTyped(500, CodeInternal, "database error", true, reqID)
		}
		var out ListJobsOut
		for i := range rows {
			out.Body.Jobs = append(out.Body.Jobs, jobRowToAPIView(&rows[i], cfg))
		}
		return &out, nil
	})
}

func isJobAdmin(kc apikeys.KeyContext, cfg Config) bool {
	for _, o := range cfg.JobAdminOwners {
		if o == kc.Owner {
			return true
		}
	}
	return false
}

// randomWebhookSecret returns URL-safe random bytes as string for signing (32 bytes).