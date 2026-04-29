package main

import (
	"encoding/json"
	"time"

	"github.com/rverton/webanalyze/internal/asyncjobs"
)

// JobErrorPayload matches job.error in API responses.
type JobErrorPayload struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// JobDeliveryInfo is the delivery subsection of GET /v1/jobs/{id}.
type JobDeliveryInfo struct {
	CallbackURL      *string    `json:"callback_url,omitempty"`
	Attempts         int        `json:"attempts"`
	LastAttemptAt    *time.Time `json:"last_attempt_at"`
	NextAttemptAt    *time.Time `json:"next_attempt_at"`
	Status           string     `json:"status"`
	LastResponseCode *int       `json:"last_response_code,omitempty"`
	LastError        *string    `json:"last_error,omitempty"`
}

// JobStatusPayload is the full job object in poll and webhook bodies.
type JobStatusPayload struct {
	JobID        string             `json:"job_id"`
	Status       string             `json:"status"`
	SubmittedAt  time.Time          `json:"submitted_at"`
	StartedAt    *time.Time         `json:"started_at,omitempty"`
	CompletedAt  *time.Time         `json:"completed_at,omitempty"`
	Attempts     int                `json:"attempts"`
	Input        json.RawMessage    `json:"input"`
	Options      json.RawMessage    `json:"options"`
	Metadata     json.RawMessage    `json:"metadata,omitempty"`
	Result       *AnalyzeSuccessResponse `json:"result,omitempty"`
	Error        *JobErrorPayload   `json:"error,omitempty"`
	Delivery     JobDeliveryInfo    `json:"delivery"`
}

func jobRowToAPIView(j *asyncjobs.JobRow, _ Config) JobStatusPayload {
	var meta json.RawMessage
	if len(j.MetadataJSON) > 0 {
		meta = j.MetadataJSON
	}
	var result *AnalyzeSuccessResponse
	if len(j.ResultJSON) > 0 && j.Status == asyncjobs.StatusSucceeded {
		var r AnalyzeSuccessResponse
		if json.Unmarshal(j.ResultJSON, &r) == nil {
			result = &r
		}
	}
	var errPay *JobErrorPayload
	if len(j.ErrorJSON) > 0 {
		var e JobErrorPayload
		if json.Unmarshal(j.ErrorJSON, &e) == nil && e.Code != "" {
			errPay = &e
		}
	}
	d := JobDeliveryInfo{
		Attempts: j.DeliveryAttempts,
		Status:   j.DeliveryStatus,
	}
	if j.CallbackURL.Valid && j.CallbackURL.String != "" {
		u := j.CallbackURL.String
		d.CallbackURL = &u
	}
	if j.DeliveryLastAttemptAt.Valid {
		t := j.DeliveryLastAttemptAt.Time
		d.LastAttemptAt = &t
	}
	if j.DeliveryNextAttemptAt.Valid {
		t := j.DeliveryNextAttemptAt.Time
		d.NextAttemptAt = &t
	}
	if j.DeliveryLastCode.Valid {
		c := int(j.DeliveryLastCode.Int32)
		d.LastResponseCode = &c
	}
	if j.DeliveryLastError.Valid && j.DeliveryLastError.String != "" {
		s := j.DeliveryLastError.String
		d.LastError = &s
	}
	var startPtr, compPtr *time.Time
	if j.StartedAt.Valid {
		t := j.StartedAt.Time
		startPtr = &t
	}
	if j.CompletedAt.Valid {
		t := j.CompletedAt.Time
		compPtr = &t
	}
	return JobStatusPayload{
		JobID:       j.ID,
		Status:      j.Status,
		SubmittedAt: j.SubmittedAt.UTC().Truncate(time.Millisecond),
		StartedAt:   startPtr,
		CompletedAt: compPtr,
		Attempts:    j.Attempts,
		Input:       j.InputJSON,
		Options:     j.OptionsJSON,
		Metadata:    meta,
		Result:      result,
		Error:       errPay,
		Delivery:    d,
	}
}
