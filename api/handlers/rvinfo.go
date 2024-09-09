// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"log/slog"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo-server/internal/db"
	"github.com/fido-device-onboard/go-fdo-server/internal/rvinfo"
)

var mu sync.Mutex

func RvInfoHandler(srv *fdo.Server, rvInfo *[][]fdo.RvInstruction) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Received request", "method", r.Method, "path", r.URL.Path)
		switch r.Method {
		case http.MethodGet:
			getRvData(w, r)
		case http.MethodPost:
			createRvData(w, r, rvInfo, srv)
		case http.MethodPut:
			updateRvData(w, r, rvInfo, srv)
		default:
			slog.Debug("Method not allowed", "method", r.Method, "path", r.URL.Path)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func getRvData(w http.ResponseWriter, _ *http.Request) {
	slog.Debug("Fetching rvData")
	rvData, err := db.FetchDataFromDB()
	if err != nil {
		if err == sql.ErrNoRows {
			slog.Debug("No rvData found")
			http.Error(w, "No rvData found", http.StatusNotFound)
		} else {
			slog.Debug("Error fetching rvData", "error", err)
			http.Error(w, "Error fetching rvData", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rvData)
}

func createRvData(w http.ResponseWriter, r *http.Request, rvInfo *[][]fdo.RvInstruction, srv *fdo.Server) {
	mu.Lock()
	defer mu.Unlock()

	rvData, err := parseRequestBody(r)
	if err != nil {
		slog.Debug("Error parsing request body", "error", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if exists, err := db.CheckDataExists(); err != nil {
		slog.Debug("Error checking rvData existence", "error", err)
		http.Error(w, "Error processing rvData", http.StatusInternalServerError)
		return
	} else if exists {
		slog.Debug("rvData already exists, cannot create new entry")
		http.Error(w, "rvData already exists", http.StatusConflict)
		return
	}

	if err := db.InsertData(rvData); err != nil {
		slog.Debug("Error inserting rvData", "error", err)
		http.Error(w, "Error inserting rvData", http.StatusInternalServerError)
		return
	}

	slog.Debug("rvData created")

	if err := rvinfo.UpdateRvInfoFromDB(rvInfo); err != nil {
		slog.Debug("Error updating RVInfo", "error", err)
		http.Error(w, "Error updating RVInfo", http.StatusInternalServerError)
		return
	}

	srv.RvInfo = *rvInfo
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rvData)
}

func updateRvData(w http.ResponseWriter, r *http.Request, rvInfo *[][]fdo.RvInstruction, srv *fdo.Server) {
	mu.Lock()
	defer mu.Unlock()

	rvData, err := parseRequestBody(r)
	if err != nil {
		slog.Debug("Error parsing request body", "error", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if exists, err := db.CheckDataExists(); err != nil {
		slog.Debug("Error checking rvData existence", "error", err)
		http.Error(w, "Error processing rvData", http.StatusInternalServerError)
		return
	} else if !exists {
		slog.Debug("No rvData found to update")
		http.Error(w, "No rvData found", http.StatusNotFound)
		return
	}

	if err := db.UpdateDataInDB(rvData); err != nil {
		slog.Debug("Error updating rvData", "error", err)
		http.Error(w, "Error updating rvData", http.StatusInternalServerError)
		return
	}

	slog.Debug("rvData updated")

	if err := rvinfo.UpdateRvInfoFromDB(rvInfo); err != nil {
		slog.Debug("Error updating RVInfo", "error", err)
		http.Error(w, "Error updating RVInfo", http.StatusInternalServerError)
		return
	}

	srv.RvInfo = *rvInfo
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rvData)
}

func parseRequestBody(r *http.Request) (db.Data, error) {
	var rvData db.Data
	contentType := r.Header.Get("Content-Type")
	if contentType == "text/plain" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return rvData, fmt.Errorf("error reading body: %w", err)
		}
		var rawData interface{}
		if err := json.Unmarshal(body, &rawData); err != nil {
			return rvData, fmt.Errorf("error unmarshalling body: %w", err)
		}
		rvData.Value = rawData
	} else {
		if err := json.NewDecoder(r.Body).Decode(&rvData); err != nil {
			return rvData, fmt.Errorf("error decoding JSON: %w", err)
		}
	}
	return rvData, nil
}
