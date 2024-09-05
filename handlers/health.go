package handlers

import (
	"encoding/json"
	"net/http"
)

type Health struct {
	Version string `json:"version"`
	Status  string `json:"status"`
}

func NewHealth() *Health {
	return &Health{"1.1", "OK"}
}

func (h *Health) ServeHTTP(rw http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(rw, r.Method+" not allowed", http.StatusMethodNotAllowed)
		return
	}

	healthCheck, err := json.Marshal(h)
	if err != nil {
		http.Error(rw, "Health check failed", http.StatusServiceUnavailable)
	}
	rw.Write(healthCheck)
}
