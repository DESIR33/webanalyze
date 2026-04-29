package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rverton/webanalyze"
	"github.com/rverton/webanalyze/internal/dnswhois"
)

// BulkAnalyzeRequestBody is POST /v1/analyze/bulk body.
type BulkAnalyzeRequestBody struct {
	URLs    []string       `json:"urls" minItems:"1" doc:"URLs to analyze, in order (max N per WA_MAX_BULK_URLS)"`
	Options AnalyzeOptions `json:"options,omitempty" doc:"Applied to every URL in the batch"`
}

// BulkAnalyzeItem is one entry in the bulk response (same order as input urls).
type BulkAnalyzeItem struct {
	OK    bool                    `json:"ok"`
	Data  *AnalyzeSuccessResponse `json:"data,omitempty"`
	Error *ErrorPayload           `json:"error,omitempty"`
}

// BulkAnalyzeSuccessResponse is the JSON body for 200 from POST /v1/analyze/bulk.
type BulkAnalyzeSuccessResponse struct {
	RequestID string            `json:"request_id"`
	Results   []BulkAnalyzeItem `json:"results"`
}

func registerBulkAnalyze(api huma.API, cfg Config, wa *webanalyze.WebAnalyzer, pool *scanPool, sideRT *dnswhois.SideRuntime) {
	type Input struct {
		RequestID string `header:"X-Request-ID" doc:"Optional correlation ID; echoed in response"`
		Body      BulkAnalyzeRequestBody
	}

	type Output struct {
		RequestIDHeader string `header:"X-Request-ID"`
		Body            func(huma.Context)
	}

	huma.Register(api, huma.Operation{
		OperationID:  "analyzeBulk",
		Method:       http.MethodPost,
		Path:         "/v1/analyze/bulk",
		Summary:      "Analyze multiple URLs in one request (worker-pool limited, order preserved)",
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

		urls := input.Body.URLs
		if len(urls) == 0 {
			return nil, errTyped(400, CodeBatchEmpty, "urls must contain at least one entry", false, reqID)
		}
		if len(urls) > cfg.MaxBulkURLs {
			return nil, errTyped(400, CodeBatchTooLarge, "urls exceeds configured maximum for bulk analyze", false, reqID)
		}

		results := make([]BulkAnalyzeItem, len(urls))
		var wg sync.WaitGroup
		for i := range urls {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				rawURL := strings.TrimSpace(urls[idx])
				u, err := url.Parse(rawURL)
				if err != nil || u.Scheme == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
					results[idx] = BulkAnalyzeItem{
						OK: false,
						Error: &ErrorPayload{
							Code:      CodeInvalidURL,
							Message:   "url must be an absolute http or https URL",
							Retryable: false,
							RequestID: reqID,
						},
					}
					return
				}

				data, scanErr := runAnalyzeScan(ctx, reqID, cfg, wa, pool, sideRT, u, rawURL, input.Body.Options, input.Body.Options.Fresh)
				if scanErr != nil {
					var te *TypedHTTPError
					if errors.As(scanErr, &te) {
						results[idx] = BulkAnalyzeItem{
							OK:    false,
							Error: &te.Payload,
						}
					} else {
						results[idx] = BulkAnalyzeItem{
							OK: false,
							Error: &ErrorPayload{
								Code:      CodeInternal,
								Message:   scanErr.Error(),
								Retryable: true,
								RequestID: reqID,
							},
						}
					}
					if results[idx].Error != nil && results[idx].Error.RequestID == "" {
						results[idx].Error.RequestID = reqID
					}
					return
				}
				data.RequestID = reqID

				results[idx] = BulkAnalyzeItem{
					OK:   true,
					Data: data,
				}
			}(i)
		}
		wg.Wait()

		payload := BulkAnalyzeSuccessResponse{
			RequestID: reqID,
			Results:   results,
		}

		return &Output{
			RequestIDHeader: reqID,
			Body: func(hctx huma.Context) {
				hctx.SetHeader("Content-Type", "application/json")
				_ = json.NewEncoder(hctx.BodyWriter()).Encode(payload)
			},
		}, nil
	})
}
