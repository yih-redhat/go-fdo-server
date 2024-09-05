package main

import (
	"net/http"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo-server/cmd/handlers"
	transport "github.com/fido-device-onboard/go-fdo/http"
)

// HTTPHandler handles HTTP requests
type HTTPHandler struct {
	svc    *fdo.Server
	rvInfo *[][]fdo.RvInstruction
}

// NewHTTPHandler creates a new HTTPHandler
func NewHTTPHandler(svc *fdo.Server, rvInfo *[][]fdo.RvInstruction) *HTTPHandler {
	return &HTTPHandler{svc: svc, rvInfo: rvInfo}
}

// RegisterRoutes registers the routes for the HTTP server
func (h *HTTPHandler) RegisterRoutes() *http.ServeMux {
	handler := http.NewServeMux()
	handler.Handle("POST /fdo/101/msg/{msg}", &transport.Handler{Responder: h.svc})
	handler.HandleFunc("/api/v1/rvinfo", handlers.RvInfoHandler(h.svc, h.rvInfo))
	handler.HandleFunc("/api/v1/vouchers", handlers.GetVoucherHandler)
	handler.HandleFunc("/api/v1/owner/vouchers", handlers.InsertVoucherHandler)
	handler.HandleFunc("/health", handlers.HealthHandler)
	return handler
}
