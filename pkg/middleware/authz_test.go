package middleware

import (
	"net/http"
	"net/http/httptest"
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
	t.Setenv("PROXY_URL", "https://fakeproxy")
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

func TestAuthzMissingBearerValue(t *testing.T) {
	t.Setenv("PROXY_URL", "https://fakeproxy")
	r := httptest.NewRequest("GET", "/v2/org/ns/comp/manifests/latest", nil)
	r.Header.Set("Authorization", "Bearer")
	rr := httptest.NewRecorder()

	authzHandler.ServeHTTP(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected code %d, but got %d", http.StatusUnauthorized, rr.Code)
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

func TestAuthzRejectsUnscopedPath(t *testing.T) {
	t.Setenv("BACKEND_NAMESPACE", "namespace1")
	paths := []string{
		"/v2/namespace1/manifests/latest",
		"/v2/namespace1/tenant/app/extra/manifests/latest",
		"/v2/namespace1/tenant/app/manifests/../../other/manifests/latest",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			called := false
			handler := Authz(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Authorization", "Bearer "+tests.GenToken(time.Now(), "bar"))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, r)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("Expected code %d, but got %d", http.StatusUnauthorized, rr.Code)
			}
			if called {
				t.Error("authorized handler was called for a path outside the repository schema")
			}
		})
	}
}

func TestAuthzInvalidNamespace(t *testing.T) {
	r := httptest.NewRequest("GET", "/v2/namespace2/tenant/app/manifests/latest", nil)
	r.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()
	t.Setenv("BACKEND_NAMESPACE", "namespace1")
	authzHandler.ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected code %d, but got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestAuthz(t *testing.T) {
	r := httptest.NewRequest("GET", "/v2/namespace1/tenant/app/manifests/latest", nil)
	token := tests.GenToken(time.Now(), "bar")
	r.Header.Set("Authorization", "Bearer "+token)
	t.Setenv("BACKEND_NAMESPACE", "namespace1")

	authzTests := []struct {
		name              string
		openshiftResponse []tests.Response
		wantAuthorized    bool
	}{
		{
			name: "Successful authorization",
			openshiftResponse: []tests.Response{
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
			openshiftResponse: []tests.Response{
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
			openshiftResponse: []tests.Response{
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
			t.Setenv("CLUSTER_URL", server.URL)
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
