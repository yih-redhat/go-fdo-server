package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"

	"github.com/fido-device-onboard/go-fdo"
)

func updateRvInfoHandler(srv *fdo.Server, rvInfo *[][]fdo.RvInstruction) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received %s request for %s", r.Method, r.URL.Path)
		switch r.Method {
		case http.MethodGet:
			getData(w, r)
		case http.MethodPost:
			createData(w, r, rvInfo, srv)
		case http.MethodPut:
			updateData(w, r, rvInfo, srv)
		default:
			log.Printf("Method %s not allowed for %s", r.Method, r.URL.Path)
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
			log.Printf("Voucher not found for GUID: %s", guidHex)
			http.Error(w, "Voucher not found", http.StatusNotFound)
		} else {
			log.Printf("Error querying database: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	ownerKeys, err := fetchOwnerKeys()
	if err != nil {
		log.Printf("Error querying owner_keys: %v", err)
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
		log.Printf("Error marshalling JSON: %v", err)
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
	log.Printf("Inserting voucher with GUID: %s", guidHex)

	if err := insertVoucher(request.Voucher); err != nil {
		log.Printf("Error inserting into database: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := updateOwnerKeys(request.OwnerKeys); err != nil {
		log.Printf("Error updating owner key in database: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Voucher inserted and owner keys updated successfully"))
}

func getData(w http.ResponseWriter, _ *http.Request) {
	log.Println("Fetching data")
	data, err := fetchDataFromDB()
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("No data found")
			http.Error(w, "No data found", http.StatusNotFound)
		} else {
			log.Printf("Error fetching data: %v", err)
			http.Error(w, "Error fetching data", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func createData(w http.ResponseWriter, r *http.Request, rvInfo *[][]fdo.RvInstruction, srv *fdo.Server) {
	mu.Lock()
	defer mu.Unlock()

	log.Println("Creating new data")

	data, err := parseRequestBody(r)
	if err != nil {
		log.Printf("Error parsing request body: %v", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if exists, err := checkDataExists(); err != nil {
		log.Printf("Error checking data existence: %v", err)
		http.Error(w, "Error processing data", http.StatusInternalServerError)
		return
	} else if exists {
		log.Println("Data already exists, cannot create new entry")
		http.Error(w, "Data already exists", http.StatusConflict)
		return
	}

	if err := insertData(data); err != nil {
		log.Printf("Error inserting data: %v", err)
		http.Error(w, "Error inserting data", http.StatusInternalServerError)
		return
	}

	log.Println("Data created")

	if err := updateRvInfoFromDB(rvInfo); err != nil {
		log.Printf("Error updating RVInfo: %v", err)
		http.Error(w, "Error updating RVInfo", http.StatusInternalServerError)
		return
	}

	srv.RvInfo = *rvInfo
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func updateData(w http.ResponseWriter, r *http.Request, rvInfo *[][]fdo.RvInstruction, srv *fdo.Server) {
	mu.Lock()
	defer mu.Unlock()

	log.Println("Updating data")

	data, err := parseRequestBody(r)
	if err != nil {
		log.Printf("Error parsing request body: %v", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if exists, err := checkDataExists(); err != nil {
		log.Printf("Error checking data existence: %v", err)
		http.Error(w, "Error processing data", http.StatusInternalServerError)
		return
	} else if !exists {
		log.Println("No data found to update")
		http.Error(w, "No data found", http.StatusNotFound)
		return
	}

	if err := updateDataInDB(data); err != nil {
		log.Printf("Error updating data: %v", err)
		http.Error(w, "Error updating data", http.StatusInternalServerError)
		return
	}

	log.Println("Data updated")

	if err := updateRvInfoFromDB(rvInfo); err != nil {
		log.Printf("Error updating RVInfo: %v", err)
		http.Error(w, "Error updating RVInfo", http.StatusInternalServerError)
		return
	}

	srv.RvInfo = *rvInfo
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
