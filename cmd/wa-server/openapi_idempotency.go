package main

import (
	"encoding/json"

	"github.com/danielgtaylor/huma/v2"
)

func registerOpenAPIIdempotency(api huma.API) {
	o := api.OpenAPI()
	if o == nil || o.Paths == nil {
		return
	}
	for _, p := range []string{"/v1/analyze", "/v1/analyze/bulk", "/v1/analyze/async"} {
		patchPostIdempotency(o, p)
	}
}

func patchPostIdempotency(o *huma.OpenAPI, path string) {
	item := o.Paths[path]
	if item == nil || item.Post == nil {
		return
	}
	op := item.Post
	op.Parameters = append(op.Parameters, idemRequestHeaderParam())

	if op.Responses == nil {
		op.Responses = map[string]*huma.Response{}
	}
	mergeIdempotencyErrorResponses(op.Responses)
	addIdempotencyResponseHeaders(op.Responses)
}

func idemRequestHeaderParam() *huma.Param {
	max255 := 255
	return &huma.Param{
		Name:        "Idempotency-Key",
		In:          "header",
		Description: "Optional opaque ASCII key (1–255 chars, no whitespace). Same key + same JSON body replays the prior response for 24h. Namespace is per API key.",
		Required:    false,
		Schema: &huma.Schema{
			Type:      "string",
			MaxLength: &max255,
		},
		Example: "01JABCD1234567890ABCDEFGH",
	}
}

func mergeIdempotencyErrorResponses(res map[string]*huma.Response) {
	exampleInvalidKey, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"code": CodeInvalidIdempotencyKey, "message": "Idempotency-Key must be 1–255 ASCII characters without whitespace or control characters",
			"retryable": false, "request_id": "01JEXAMPLEIDEMPOTENCY1",
		},
	})
	exampleConflict, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"code": CodeIdempotencyKeyConflict, "message": "Idempotency-Key was reused with a different request body",
			"retryable": false, "request_id": "01JEXAMPLEIDEMPOTENCY2",
		},
	})
	exampleInProgress, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"code": CodeIdempotencyInProgress, "message": "Original request with this Idempotency-Key is still in progress",
			"retryable": true, "request_id": "01JEXAMPLEIDEMPOTENCY3",
		},
	})

	res["400"] = mergeResponseKeepContent(res["400"], &huma.Response{
		Description: "Malformed Idempotency-Key header (INVALID_IDEMPOTENCY_KEY) or invalid JSON (INVALID_PAYLOAD)",
		Content: map[string]*huma.MediaType{
			"application/json": {
				Schema:  errorEnvelopeSchema(),
				Example: json.RawMessage(exampleInvalidKey),
			},
		},
	})
	res["409"] = mergeResponseKeepContent(res["409"], &huma.Response{
		Description: "Same idempotency key still in flight (IDEMPOTENCY_IN_PROGRESS). Retry after Retry-After.",
		Content: map[string]*huma.MediaType{
			"application/json": {
				Schema:  errorEnvelopeSchema(),
				Example: json.RawMessage(exampleInProgress),
			},
		},
	})
	res["422"] = mergeResponseKeepContent(res["422"], &huma.Response{
		Description: "Idempotency-Key reused with different body (IDEMPOTENCY_KEY_CONFLICT)",
		Content: map[string]*huma.MediaType{
			"application/json": {
				Schema:  errorEnvelopeSchema(),
				Example: json.RawMessage(exampleConflict),
			},
		},
	})
}

func errorEnvelopeSchema() *huma.Schema {
	return &huma.Schema{
		Type: "object",
		Properties: map[string]*huma.Schema{
			"error": {
				Type: "object",
				Properties: map[string]*huma.Schema{
					"code":      {Type: "string"},
					"message":   {Type: "string"},
					"retryable": {Type: "boolean"},
					"request_id": {
						Type: "string",
					},
				},
				Required: []string{"code", "message", "retryable", "request_id"},
			},
		},
		Required: []string{"error"},
	}
}

// mergeResponseKeepContent prefers existing description/content when present; fills gaps from patch.
func mergeResponseKeepContent(existing *huma.Response, patch *huma.Response) *huma.Response {
	if existing == nil {
		return patch
	}
	out := *existing
	if out.Description == "" {
		out.Description = patch.Description
	}
	if out.Content == nil {
		out.Content = patch.Content
	}
	return &out
}

func addIdempotencyResponseHeaders(res map[string]*huma.Response) {
	for _, r := range res {
		if r == nil {
			continue
		}
		if r.Headers == nil {
			r.Headers = map[string]*huma.Param{}
		}
		mergeHeader(r.Headers, "Idempotency-Key", "Echoed when the request carried Idempotency-Key", false, "string")
		mergeHeader(r.Headers, "X-Idempotency-Replayed", "true if body/status were served from cache", false, "string")
		mergeHeader(r.Headers, "X-Idempotency-First-Seen-At", "First time this idempotency key was recorded (RFC3339)", false, "string")
		mergeHeader(r.Headers, "X-Idempotency-Original-Request-Id", "Present on replay: request_id of the original execution", false, "string")
		mergeHeader(r.Headers, "X-Idempotency-Stored", "Whether the response was written to the idempotency cache", false, "string")
		mergeHeader(r.Headers, "X-Idempotency-Stored-Reason", "When not stored: e.g. response_too_large, server_error", false, "string")
	}
}

func mergeHeader(h map[string]*huma.Param, name, desc string, required bool, typ string) {
	if _, ok := h[name]; ok {
		return
	}
	h[name] = &huma.Param{
		Name:        name,
		In:          "header",
		Description: desc,
		Required:    required,
		Schema:      &huma.Schema{Type: typ},
	}
}
