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

func (health *Health) ServeHTTP(rw http.ResponseWriter, request *http.Request) {

	if request.Method != http.MethodGet {
		http.Error(rw, request.Method+" not allowed", http.StatusMethodNotAllowed)
		return
	}

	healthStatus, err := json.Marshal(health)
	if err != nil {
		http.Error(rw, "Health check failed", http.StatusServiceUnavailable)
	}
	rw.Write(healthStatus)
}
