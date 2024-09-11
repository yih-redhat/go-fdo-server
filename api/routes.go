// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package api

import (
	"net/http"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo-server/api/handlers"
	transport "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

// HTTPHandler handles HTTP requests
type HTTPHandler struct {
	svc       *fdo.Server
	rvInfo    *[][]fdo.RvInstruction
	ownerInfo []fdo.RvTO2Addr
	state     *sqlite.DB
}

// NewHTTPHandler creates a new HTTPHandler
func NewHTTPHandler(svc *fdo.Server, rvInfo *[][]fdo.RvInstruction, ownerInfo []fdo.RvTO2Addr, state *sqlite.DB) *HTTPHandler {
	return &HTTPHandler{svc: svc, rvInfo: rvInfo, ownerInfo: ownerInfo, state: state}
}

// RegisterRoutes registers the routes for the HTTP server
func (h *HTTPHandler) RegisterRoutes() *http.ServeMux {
	handler := http.NewServeMux()
	handler.Handle("POST /fdo/101/msg/{msg}", &transport.Handler{Responder: h.svc})
	handler.HandleFunc("/api/v1/rvinfo", handlers.RvInfoHandler(h.svc, h.rvInfo))
	handler.HandleFunc("/api/v1/owner/redirect", handlers.OwnInfoHandler)
	handler.HandleFunc("/api/v1/to0/", handlers.To0Handler(h.svc, h.ownerInfo, h.state))
	handler.HandleFunc("/api/v1/vouchers", handlers.GetVoucherHandler)
	handler.HandleFunc("/api/v1/owner/vouchers", handlers.InsertVoucherHandler(h.svc, h.rvInfo))
	handler.HandleFunc("/health", handlers.HealthHandler)
	return handler
}
