package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistryHandlerNoAuth(t *testing.T) {
	r := httptest.NewRequest("GET", "/v2/", nil)
	rr := httptest.NewRecorder()
	http.HandlerFunc(RegistryHandler).ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected code %d, but got %d", http.StatusOK, rr.Code)
	}
}

type TestAuth struct {
	username    string
}

func NewTestAuth(user string) *TestAuth {
	return &TestAuth{username: user}
}

func (a *TestAuth) AuthorizationHeader(bp *BackendProxy, repo string) (string, error) {
	if a.username != "" {
		return "Bearer token-for-" + a.username + "-" + repo, nil
	} 
	return "", errors.New("registry error")
	
}

func TestRegistryHandler(t *testing.T) {
	registryTests := []struct{
		name           string
		username       string
		expectedStatus int
	}{
		{
			name: "Token auth succeeds",
			username: "test",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Token auth fails",
			username: "",
			expectedStatus: http.StatusServiceUnavailable,
		},
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "Bearer token-for-test-foobar"
		if r.Header.Get("Authorization") != expected {
			t.Errorf("Incorrect Authorization %s", r.Header)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	for _, tt := range registryTests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewTestAuth(tt.username)
			bp := BackendProxy{URL: origin.URL, Auth: auth}
			BackendRegistry = &bp

			r := httptest.NewRequest("GET", "/v2/foobar/manifests/latest", nil)
			rr := httptest.NewRecorder()
			http.HandlerFunc(RegistryHandler).ServeHTTP(rr, r)
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected code %d, but got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}
