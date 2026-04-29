package main

import (
	"net/url"
	"strings"

	"github.com/oklog/ulid/v2"
)

type ctxKey string

const (
	ctxRequestID   ctxKey = "request_id"
	ctxKeyID       ctxKey = "key_id"
	ctxTargetHost  ctxKey = "target_url_host"
)

func newRequestID() string {
	return ulid.Make().String()
}

func hostOnlyFromURLString(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" {
		return ""
	}
	h := u.Hostname()
	return h
}
