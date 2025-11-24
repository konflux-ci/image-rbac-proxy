package utils

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse represents an error formatted for the Distribution API
type ErrorResponse struct {
	Errors []Error `json:"errors"`
}

// Error represents an error represented by the Distribution API
type Error struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Detail  []string `json:"detail,omitempty"`
}

// Unauthorized is returned when authentication is required
const Unauthorized = "UNAUTHORIZED"

// Unavailable is returned when there is a backend service error
const Unavailable = "UNAVAILABLE"

// ErrorString returns a JSON string representation of an ErrorResponse
func ErrorString(code, msg string) string {
	e := Error{
		Code:    code,
		Message: msg,
	}
	resp, _ := json.Marshal(ErrorResponse{[]Error{e}})
	return string(resp)
}

// ErrorHTTPResponse writes an error response that is understood by Distribution clients
func ErrorHTTPResponse(w http.ResponseWriter, ec string, msg string) {
	body := ErrorString(ec, msg)

	var status int
	switch ec {
	case Unauthorized:
		status = http.StatusUnauthorized
	case Unavailable:
		status = http.StatusServiceUnavailable
	default:
		status = http.StatusInternalServerError
	}

	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(status)
	w.Write([]byte(body))
}
