package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"slices"

	"image-rbac-proxy/pkg/tests"
)

func TestOauthHandler(t *testing.T) {
	r := httptest.NewRequest("GET", "/oauth", nil)
	rr := httptest.NewRecorder()
	mockServer := tests.NewMockOIDCServer()
	defer mockServer.Close()
	os.Setenv("DEX_URL", mockServer.Server.URL)
	os.Setenv("DEX_CLIENT_ID", "test-client")
	os.Setenv("DEX_CLIENT_SECRET", "test-secret")
	os.Setenv("PROXY_URL", "https://fakeproxy")

	OauthHandler(rr, r)
	if rr.Code != http.StatusFound {
		t.Errorf("Expected auth %d, but got %d", http.StatusFound, rr.Code)
	}
	location := rr.Header().Get("Location")
	if location == "" {
		t.Error("Expected redirect but got no Location header")
	}
}

func TestOauthCallbackHandler(t *testing.T) {
	r := httptest.NewRequest("GET", "/oauth/callback?code=fakecode", nil)
	rr := httptest.NewRecorder()
	mockServer := tests.NewMockOIDCServer()
	defer mockServer.Close()
	os.Setenv("DEX_URL", mockServer.Server.URL)
	os.Setenv("DEX_CLIENT_ID", "test-client")
	os.Setenv("DEX_CLIENT_SECRET", "test-secret")
	os.Setenv("PROXY_URL", "https://fakeproxy")

	OauthCallbackHandler(rr, r)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected auth %d, but got %d", http.StatusOK, rr.Code)
	}

	if rr.Body.String() != "mock-id-token" {
		t.Errorf("Incorrect token in response: %s", rr.Body)
	}
}

func TestVerifyIDToken(t *testing.T) {
	mockServer := tests.NewMockOIDCServer()
	defer mockServer.Close()
	os.Setenv("DEX_URL", mockServer.Server.URL)
	os.Setenv("DEX_CLIENT_ID", "test-client")
	token, _ := mockServer.GenIDToken("test-client", "user1", []string{"group1", "group2"})

	email, groups := VerifyIDToken(token)

	if email != "user1" {
		t.Errorf("Incorrect email: %s", email)
	}
	if !slices.Equal(groups, []string{"group1", "group2"}){
		t.Errorf("Incorrect groups: %s", groups)
	}
}
