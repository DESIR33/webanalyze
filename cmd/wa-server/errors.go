package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/rverton/webanalyze"
)

// Error codes published in OpenAPI (stable strings).
const (
	CodeInvalidURL        = "INVALID_URL"
	CodeDNSFail           = "DNS_FAIL"
	CodeTLSFail           = "TLS_FAIL"
	CodeTimeout           = "TIMEOUT"
	CodeBlocked403        = "BLOCKED_403"
	CodeBlockedCaptcha    = "BLOCKED_CAPTCHA"
	CodeEmptyPage         = "EMPTY_PAGE"
	CodeInternal          = "INTERNAL"
	CodeUnauthorized      = "UNAUTHORIZED"
	CodeRateLimited       = "RATE_LIMITED"
	CodeTargetHostLimited = "TARGET_HOST_LIMITED"
	CodeTargetHostCircuit = "TARGET_HOST_CIRCUIT_OPEN"
	CodeBatchEmpty        = "BATCH_EMPTY"
	CodeBatchTooLarge     = "BATCH_TOO_LARGE"
)

// ErrorPayload is the typed error envelope (R5).
type ErrorPayload struct {
	Code      string `json:"code" doc:"Stable error code" enum:"INVALID_URL,DNS_FAIL,TLS_FAIL,TIMEOUT,BLOCKED_403,BLOCKED_CAPTCHA,EMPTY_PAGE,INTERNAL,UNAUTHORIZED,RATE_LIMITED,TARGET_HOST_LIMITED,TARGET_HOST_CIRCUIT_OPEN,BATCH_EMPTY,BATCH_TOO_LARGE"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	RequestID string `json:"request_id"`
}

// TypedHTTPError implements huma.StatusError and JSON-marshals to R5 shape.
type TypedHTTPError struct {
	Status  int
	Payload ErrorPayload
}

func (e *TypedHTTPError) Error() string {
	return e.Payload.Message
}

func (e *TypedHTTPError) GetStatus() int {
	return e.Status
}

func (e *TypedHTTPError) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"error": e.Payload})
}

func errTyped(status int, code, msg string, retry bool, reqID string) *TypedHTTPError {
	return &TypedHTTPError{
		Status: status,
		Payload: ErrorPayload{
			Code:      code,
			Message:   msg,
			Retryable: retry,
			RequestID: reqID,
		},
	}
}

func classifyScanError(reqID string, err error) *TypedHTTPError {
	if err == nil {
		return nil
	}
	if errors.Is(err, errTargetHostCircuitOpen) {
		return errTyped(503, CodeTargetHostCircuit, "Target host is temporarily unavailable due to repeated failures; try again later", true, reqID)
	}
	if errors.Is(err, errTargetHostRateLimited) {
		return errTyped(429, CodeTargetHostLimited, "Too many concurrent or queued requests to this target host for the configured per-host rate", true, reqID)
	}
	if errors.Is(err, webanalyze.ErrBlocked403) {
		return errTyped(502, CodeBlocked403, "Server returned 403 Forbidden", true, reqID)
	}
	if errors.Is(err, webanalyze.ErrCaptchaBlocked) {
		return errTyped(502, CodeBlockedCaptcha, "Page appears to be a CAPTCHA or bot challenge", true, reqID)
	}
	if errors.Is(err, webanalyze.ErrEmptyPage) {
		return errTyped(502, CodeEmptyPage, "Response body was empty", true, reqID)
	}
	if errors.Is(err, webanalyze.ErrHTMLTooLarge) {
		return errTyped(502, CodeInternal, err.Error(), false, reqID)
	}

	s := err.Error()
	if strings.Contains(s, "Failed to retrieve:") {
		return classifyFetchError(reqID, err)
	}

	return errTyped(500, CodeInternal, "Analysis failed", false, reqID)
}

func classifyFetchError(reqID string, err error) *TypedHTTPError {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return errTyped(502, CodeDNSFail, "DNS resolution failed", true, reqID)
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if errors.Is(urlErr.Err, context.DeadlineExceeded) {
			return errTyped(504, CodeTimeout, "Request timed out while contacting the target", true, reqID)
		}
		if ne, ok := urlErr.Err.(net.Error); ok && ne.Timeout() {
			return errTyped(504, CodeTimeout, "Request timed out while contacting the target", true, reqID)
		}
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return errTyped(504, CodeTimeout, "Request timed out while contacting the target", true, reqID)
		}
		if _, ok := opErr.Err.(*net.DNSError); ok {
			return errTyped(502, CodeDNSFail, "DNS resolution failed", true, reqID)
		}
		if strings.Contains(strings.ToLower(opErr.Error()), "tls") ||
			strings.Contains(strings.ToLower(fmt.Sprintf("%v", opErr.Err)), "x509") {
			return errTyped(502, CodeTLSFail, "TLS handshake or certificate verification failed", true, reqID)
		}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return errTyped(504, CodeTimeout, "Request timed out while contacting the target", true, reqID)
	}

	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return errTyped(504, CodeTimeout, "Request timed out while contacting the target", true, reqID)
	}

	if strings.Contains(strings.ToLower(err.Error()), "tls") ||
		strings.Contains(strings.ToLower(err.Error()), "x509") ||
		strings.Contains(strings.ToLower(err.Error()), "certificate") {
		return errTyped(502, CodeTLSFail, "TLS handshake or certificate verification failed", true, reqID)
	}

	return errTyped(502, CodeInternal, strings.TrimPrefix(err.Error(), "Failed to retrieve: "), true, reqID)
}
