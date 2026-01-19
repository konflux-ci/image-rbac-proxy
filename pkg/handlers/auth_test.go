package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"image-rbac-proxy/pkg/tests"
)

func TestAuthHandlerNoToken(t *testing.T) {
	r := httptest.NewRequest("GET", "/auth", nil)
	rr := httptest.NewRecorder()
	AuthHandler(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected code %d, but got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestAuthHandlerServiceAccount(t *testing.T) {
	r := httptest.NewRequest("GET", "/auth", nil)
	token := tests.GenToken(time.Now(), "bar")
	r.Header.Set("Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("foo:" + token)))

	authTests := []struct {
		name              string
		openshiftResponse []tests.Response
		wantAuthenticated bool
	}{
		{
			name: "Successful authentication",
			openshiftResponse: []tests.Response {
				{
					200,
					tests.TrResponse(true, "user1"),
				},
			},
			wantAuthenticated: true,
		},
		{
			name: "TokenReview call failure",
			openshiftResponse: []tests.Response {
				{
					500,
					"Internal server error",
				},
			},
			wantAuthenticated: false,
		},
	}

	for _, tt := range authTests {
		t.Run(tt.name, func(t *testing.T) {
			server := tests.SimulateOpenShiftMaster(tt.openshiftResponse)
			os.Setenv("CLUSTER_URL", server.URL)
			rr := httptest.NewRecorder()
			AuthHandler(rr, r)

			if tt.wantAuthenticated && rr.Code != http.StatusOK {
				t.Errorf("Expected auth %d, but got %d", http.StatusOK, rr.Code)
			}
			if !tt.wantAuthenticated && rr.Code != http.StatusUnauthorized {
				t.Errorf("Expected auth %d, but got %d", http.StatusUnauthorized, rr.Code)
			}
			if rr.Code == http.StatusOK {
				data := map[string]string{}
				json.NewDecoder(rr.Body).Decode(&data)
				if data["token"] != token {
					t.Errorf("Incorrect token in response: %s", data)
				}
			}
		})
	}
}

func TestAuthHandlerUser(t *testing.T) {
	r := httptest.NewRequest("GET", "/auth", nil)
	mockServer := tests.NewMockOIDCServer()
	defer mockServer.Close()
	os.Setenv("DEX_URL", mockServer.Server.URL)
	os.Setenv("DEX_CLIENT_ID", "test-client")
	token, _ := mockServer.GenIDToken("test-client", "user1", []string{"group1", "group2"})
	r.Header.Set("Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("user1:" + token)))

	rr := httptest.NewRecorder()
	AuthHandler(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected auth %d, but got %d", http.StatusOK, rr.Code)
	}
}
