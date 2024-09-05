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
	"github.com/fido-device-onboard/go-fdo-server/cmd/db"
	"github.com/fido-device-onboard/go-fdo-server/cmd/rvinfo"
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
	slog.Debug("Fetching Data")
	Data, err := db.FetchDataFromDB()
	if err != nil {
		if err == sql.ErrNoRows {
			slog.Debug("No Data found")
			http.Error(w, "No Data found", http.StatusNotFound)
		} else {
			slog.Debug("Error fetching Data", "error", err)
			http.Error(w, "Error fetching Data", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Data)
}

func createRvData(w http.ResponseWriter, r *http.Request, rvInfo *[][]fdo.RvInstruction, srv *fdo.Server) {
	mu.Lock()
	defer mu.Unlock()

	Data, err := parseRequestBody(r)
	if err != nil {
		slog.Debug("Error parsing request body", "error", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if exists, err := db.CheckDataExists(); err != nil {
		slog.Debug("Error checking Data existence", "error", err)
		http.Error(w, "Error processing Data", http.StatusInternalServerError)
		return
	} else if exists {
		slog.Debug("Data already exists, cannot create new entry")
		http.Error(w, "Data already exists", http.StatusConflict)
		return
	}

	if err := db.InsertData(Data); err != nil {
		slog.Debug("Error inserting Data", "error", err)
		http.Error(w, "Error inserting Data", http.StatusInternalServerError)
		return
	}

	slog.Debug("Data created")

	if err := rvinfo.UpdateRvInfoFromDB(rvInfo); err != nil {
		slog.Debug("Error updating RVInfo", "error", err)
		http.Error(w, "Error updating RVInfo", http.StatusInternalServerError)
		return
	}

	srv.RvInfo = *rvInfo
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Data)
}

func updateRvData(w http.ResponseWriter, r *http.Request, rvInfo *[][]fdo.RvInstruction, srv *fdo.Server) {
	mu.Lock()
	defer mu.Unlock()

	Data, err := parseRequestBody(r)
	if err != nil {
		slog.Debug("Error parsing request body", "error", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if exists, err := db.CheckDataExists(); err != nil {
		slog.Debug("Error checking Data existence", "error", err)
		http.Error(w, "Error processing Data", http.StatusInternalServerError)
		return
	} else if !exists {
		slog.Debug("No Data found to update")
		http.Error(w, "No Data found", http.StatusNotFound)
		return
	}

	if err := db.UpdateDataInDB(Data); err != nil {
		slog.Debug("Error updating Data", "error", err)
		http.Error(w, "Error updating Data", http.StatusInternalServerError)
		return
	}

	slog.Debug("Data updated")

	if err := rvinfo.UpdateRvInfoFromDB(rvInfo); err != nil {
		slog.Debug("Error updating RVInfo", "error", err)
		http.Error(w, "Error updating RVInfo", http.StatusInternalServerError)
		return
	}

	srv.RvInfo = *rvInfo
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Data)
}

func parseRequestBody(r *http.Request) (db.Data, error) {
	var Data db.Data
	contentType := r.Header.Get("Content-Type")
	if contentType == "text/plain" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return Data, fmt.Errorf("error reading body: %w", err)
		}
		var rawData interface{}
		if err := json.Unmarshal(body, &rawData); err != nil {
			return Data, fmt.Errorf("error unmarshalling body: %w", err)
		}
		Data.Value = rawData
	} else {
		if err := json.NewDecoder(r.Body).Decode(&Data); err != nil {
			return Data, fmt.Errorf("error decoding JSON: %w", err)
		}
	}
	return Data, nil
}
