package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"image-rbac-proxy/pkg/tests"
)

var authzHandler = Authz(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})).(http.HandlerFunc)

func TestAuthzSkip(t *testing.T) {
	r := httptest.NewRequest("GET", "/foo", nil)
	rr := httptest.NewRecorder()
	authzHandler.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected code %d, but got %d", http.StatusOK, rr.Code)
	}
}

func TestAuthzNoToken(t *testing.T) {
	os.Setenv("PROXY_URL", "https://fakeproxy")
	r := httptest.NewRequest("GET", "/v2/foobar/manifests/latest", nil)
	rr := httptest.NewRecorder()
	authzHandler.ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected code %d, but got %d", http.StatusUnauthorized, rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") != "Bearer realm=\"https://fakeproxy/auth\"" {
		t.Errorf("Incorrect WWW-Authenticate %s", rr.Header())
	}
}

func TestAuthzNoRepo(t *testing.T) {
	r := httptest.NewRequest("GET", "/v2/", nil)
	r.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()
	authzHandler.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected code %d, but got %d", http.StatusOK, rr.Code)
	}
}

func TestAuthzInvalidNamespace(t *testing.T) {
	r := httptest.NewRequest("GET", "/v2/namespace2/repo1/manifests/latest", nil)
	r.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()
	os.Setenv("BACKEND_NAMESPACE", "namespace1")
	authzHandler.ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected code %d, but got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestAuthz(t *testing.T) {
	r := httptest.NewRequest("GET", "/v2/namespace1/repo1/manifests/latest", nil)
	token := tests.GenToken(time.Now(), "bar")
	r.Header.Set("Authorization", "Bearer " + token)
	os.Setenv("BACKEND_NAMESPACE", "namespace1")

	authzTests := []struct {
		name              string
		openshiftResponse []tests.Response
		wantAuthorized    bool
	}{
		{
			name: "Successful authorization",
			openshiftResponse: []tests.Response {
				{
					200,
					tests.TrResponse(true, "user1"),
				},
				{
					200,
					tests.SarResponse(true, "authorized!"),
				},
			},
			wantAuthorized: true,
		},
		{
			name: "Denied authorization",
			openshiftResponse: []tests.Response {
				{
					200,
					tests.TrResponse(true, "user1"),
				},
				{
					200,
					tests.SarResponse(false, "not authorized!"),
				},
			},
			wantAuthorized: false,
		},
		{
			name: "SubjectAccessReview call failure",
			openshiftResponse: []tests.Response {
				{
					200,
					tests.TrResponse(true, "user1"),
				},
				{
					500,
					"Internal server error",
				},
			},
			wantAuthorized: false,
		},
	}

	for _, tt := range authzTests {
		t.Run(tt.name, func(t *testing.T) {
			server := tests.SimulateOpenShiftMaster(tt.openshiftResponse)
			os.Setenv("CLUSTER_URL", server.URL)
			rr := httptest.NewRecorder()
			authzHandler.ServeHTTP(rr, r)

			if tt.wantAuthorized && rr.Code != http.StatusOK {
				t.Errorf("Expected authz %d, but got %d", http.StatusOK, rr.Code)
			}
			if !tt.wantAuthorized && rr.Code != http.StatusUnauthorized {
				t.Errorf("Expected authz %d, but got %d", http.StatusUnauthorized, rr.Code)
			}
		})
	}
}
