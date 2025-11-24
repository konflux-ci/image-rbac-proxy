package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPingHandler(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	PingHandler(rr, r)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected code %d, but got %d", http.StatusOK, rr.Code)
	}
}
