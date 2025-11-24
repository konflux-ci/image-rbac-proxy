package utils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestErrorHTTPResponse(t *testing.T) {
	var errorTests = []struct {
		name string
		code int
	}{
		{Unavailable, http.StatusServiceUnavailable},
		{Unauthorized, http.StatusUnauthorized},
		{"SomeUnexpectedCode", http.StatusInternalServerError},
	}
	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			ErrorHTTPResponse(rr, tt.name, "foo")
			if rr.Code != tt.code {
				t.Errorf("Expected code %d, but got %d", tt.code, rr.Code)
			}
			var data ErrorResponse
			json.NewDecoder(rr.Body).Decode(&data)
			if rr.Code != tt.code {
				t.Errorf("Expected code %d, but got %d", tt.code, rr.Code)
			}
			if data.Errors[0].Message != "foo" {
				t.Errorf("Expected body foo, but got %s", data)
			}
		})
	}
}
