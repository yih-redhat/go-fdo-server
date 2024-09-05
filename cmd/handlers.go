package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/fido-device-onboard/go-fdo"
	transport "github.com/fido-device-onboard/go-fdo/http"
)

var mu sync.Mutex

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
	handler.HandleFunc("/api/v1/rvinfo", rvInfoHandler(h.svc, h.rvInfo))
	handler.HandleFunc("/api/v1/vouchers", getVoucherHandler)
	handler.HandleFunc("/api/v1/owner/vouchers", insertVoucherHandler)
	return handler
}

func rvInfoHandler(srv *fdo.Server, rvInfo *[][]fdo.RvInstruction) http.HandlerFunc {
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

func getVoucherHandler(w http.ResponseWriter, r *http.Request) {
	guidHex := r.URL.Query().Get("guid")
	if guidHex == "" {
		http.Error(w, "GUID is required", http.StatusBadRequest)
		return
	}

	guid, err := hex.DecodeString(guidHex)
	if err != nil {
		http.Error(w, "Invalid GUID format", http.StatusBadRequest)
		return
	}

	voucher, err := fetchVoucher(guid)
	if err != nil {
		if err == sql.ErrNoRows {
			slog.Debug("Voucher not found", "GUID", guidHex)
			http.Error(w, "Voucher not found", http.StatusNotFound)
		} else {
			slog.Debug("Error querying database", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	ownerKeys, err := fetchOwnerKeys()
	if err != nil {
		slog.Debug("Error querying owner_keys", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := struct {
		Voucher   Voucher    `json:"voucher"`
		OwnerKeys []OwnerKey `json:"owner_keys"`
	}{
		Voucher:   voucher,
		OwnerKeys: ownerKeys,
	}

	data, err := json.Marshal(response)
	if err != nil {
		slog.Debug("Error marshalling JSON", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func insertVoucherHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Voucher   Voucher    `json:"voucher"`
		OwnerKeys []OwnerKey `json:"owner_keys"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	guidHex := hex.EncodeToString(request.Voucher.GUID)
	slog.Debug("Inserting voucher", "GUID", guidHex)

	if err := insertVoucher(request.Voucher); err != nil {
		slog.Debug("Error inserting into database", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := updateOwnerKeys(request.OwnerKeys); err != nil {
		slog.Debug("Error updating owner key in database", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(guidHex))
}

func getRvData(w http.ResponseWriter, _ *http.Request) {
	slog.Debug("Fetching data")
	data, err := fetchDataFromDB()
	if err != nil {
		if err == sql.ErrNoRows {
			slog.Debug("No data found")
			http.Error(w, "No data found", http.StatusNotFound)
		} else {
			slog.Debug("Error fetching data", "error", err)
			http.Error(w, "Error fetching data", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func createRvData(w http.ResponseWriter, r *http.Request, rvInfo *[][]fdo.RvInstruction, srv *fdo.Server) {
	mu.Lock()
	defer mu.Unlock()

	data, err := parseRequestBody(r)
	if err != nil {
		slog.Debug("Error parsing request body", "error", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if exists, err := checkDataExists(); err != nil {
		slog.Debug("Error checking data existence", "error", err)
		http.Error(w, "Error processing data", http.StatusInternalServerError)
		return
	} else if exists {
		slog.Debug("Data already exists, cannot create new entry")
		http.Error(w, "Data already exists", http.StatusConflict)
		return
	}

	if err := insertData(data); err != nil {
		slog.Debug("Error inserting data", "error", err)
		http.Error(w, "Error inserting data", http.StatusInternalServerError)
		return
	}

	slog.Debug("Data created")

	if err := updateRvInfoFromDB(rvInfo); err != nil {
		slog.Debug("Error updating RVInfo", "error", err)
		http.Error(w, "Error updating RVInfo", http.StatusInternalServerError)
		return
	}

	srv.RvInfo = *rvInfo
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func updateRvData(w http.ResponseWriter, r *http.Request, rvInfo *[][]fdo.RvInstruction, srv *fdo.Server) {
	mu.Lock()
	defer mu.Unlock()

	data, err := parseRequestBody(r)
	if err != nil {
		slog.Debug("Error parsing request body", "error", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if exists, err := checkDataExists(); err != nil {
		slog.Debug("Error checking data existence", "error", err)
		http.Error(w, "Error processing data", http.StatusInternalServerError)
		return
	} else if !exists {
		slog.Debug("No data found to update")
		http.Error(w, "No data found", http.StatusNotFound)
		return
	}

	if err := updateDataInDB(data); err != nil {
		slog.Debug("Error updating data", "error", err)
		http.Error(w, "Error updating data", http.StatusInternalServerError)
		return
	}

	slog.Debug("Data updated")

	if err := updateRvInfoFromDB(rvInfo); err != nil {
		slog.Debug("Error updating RVInfo", "error", err)
		http.Error(w, "Error updating RVInfo", http.StatusInternalServerError)
		return
	}

	srv.RvInfo = *rvInfo
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
