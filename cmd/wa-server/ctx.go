package main

import (
	"context"
	"net/url"
	"strings"

	"github.com/oklog/ulid/v2"
	"github.com/rverton/webanalyze/internal/apikeys"
)

type ctxKey string

const (
	ctxRequestID  ctxKey = "request_id"
	ctxKeyContext ctxKey = "wa_key_ctx" // apikeys.KeyContext
	ctxKeyRemain  ctxKey = "wa_remain"  // *limitRemain
	ctxTargetHost ctxKey = "target_url_host"
)

// limitRemain holds quota headers for authenticated routes.
type limitRemain struct {
	RPSLimit       int
	RPSRemaining   float64
	DailyLimit     int
	DailyRemaining float64
}

func newRequestID() string {
	return ulid.Make().String()
}

func ctxKeyFromContext(ctx context.Context) apikeys.KeyContext {
	v := ctx.Value(ctxKeyContext)
	if v == nil {
		return apikeys.KeyContext{}
	}
	kc, _ := v.(apikeys.KeyContext)
	return kc
}

func hostOnlyFromURLString(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" {
		return ""
	}
	h := u.Hostname()
	return h
}
