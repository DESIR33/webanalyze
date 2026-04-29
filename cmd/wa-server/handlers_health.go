package main

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

type serverState struct {
	ready bool
}

func registerHealth(api huma.API, st *serverState) {
	huma.Register(api, huma.Operation{
		OperationID: "health",
		Method:      http.MethodGet,
		Path:        "/v1/health",
		Summary:     "Liveness probe",
		Tags:        []string{"Health"},
	}, func(ctx context.Context, _ *struct{}) (*struct{ Body struct{} }, error) {
		return &struct{ Body struct{} }{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "ready",
		Method:      http.MethodGet,
		Path:        "/v1/ready",
		Summary:     "Readiness probe",
		Tags:        []string{"Health"},
	}, func(ctx context.Context, _ *struct{}) (*struct{ Body struct{ Status string `json:"status"` } }, error) {
		if !st.ready {
			return nil, errTyped(503, CodeInternal, "Service not ready", true, "")
		}
		return &struct{ Body struct{ Status string `json:"status"` } }{
			Body: struct{ Status string `json:"status"` }{Status: "ok"},
		}, nil
	})
}
