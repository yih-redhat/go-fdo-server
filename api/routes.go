// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package api

import (
	"net/http"

	"github.com/fido-device-onboard/go-fdo-server/api/handlers"
	transport "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

// HTTPHandler handles HTTP requests
type HTTPHandler struct {
	handler *transport.Handler
	rvInfo  *[][]protocol.RvInstruction
	state   *sqlite.DB
}

// NewHTTPHandler creates a new HTTPHandler
func NewHTTPHandler(handler *transport.Handler, rvInfo *[][]protocol.RvInstruction, state *sqlite.DB) *HTTPHandler {
	return &HTTPHandler{handler: handler, rvInfo: rvInfo, state: state}
}

// RegisterRoutes registers the routes for the HTTP server
func (h *HTTPHandler) RegisterRoutes() *http.ServeMux {
	handler := http.NewServeMux()
	handler.Handle("POST /fdo/101/msg/{msg}", h.handler)
	handler.HandleFunc("/api/v1/rvinfo", handlers.RvInfoHandler(h.rvInfo))
	handler.HandleFunc("/api/v1/owner/redirect", handlers.OwnerInfoHandler)
	handler.HandleFunc("/api/v1/to0/", handlers.To0Handler(h.rvInfo, h.state))
	handler.HandleFunc("/api/v1/vouchers", handlers.GetVoucherHandler)
	handler.HandleFunc("/api/v1/owner/vouchers", handlers.InsertVoucherHandler(h.rvInfo))
	handler.HandleFunc("/health", handlers.HealthHandler)
	return handler
}
