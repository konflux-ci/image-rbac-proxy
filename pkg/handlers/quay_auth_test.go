package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"image-rbac-proxy/pkg/tests"
	"image-rbac-proxy/pkg/utils"
)

func originAuthServer(token string) *httptest.Server {
	var originServer string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/auth" {
			u, _, _ := r.BasicAuth()
			if u == "testerror" {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				tokenResp, _ := json.Marshal(tokenResponse{Token: token})
				w.Write(tokenResp)
			}
		} else {
			realm := originServer + "/v2/auth"
			challenge := fmt.Sprintf(`Bearer realm="%s",service="service",scope="scope"`, realm)
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	originServer = s.URL
	return s
}

func TestAuthorizationHeader(t *testing.T) {
	token := tests.GenToken(time.Now(), "quay")
	origin := originAuthServer(token)
	defer origin.Close()
	utils.CacheClient = &tests.MockCache{}
	defer func() { utils.CacheClient = nil }()

	bp := BackendProxy{URL: origin.URL}
	auth := NewTokenAuth("test", "test")
	receivedToken, _ := auth.AuthorizationHeader(&bp, "foobar")
	var cachedToken string
	utils.CacheClient.Get("foobar", &cachedToken)

	if receivedToken != "Bearer " + token {
		t.Errorf("Expected token %s, but got %s", token, receivedToken)
	}
	if cachedToken != token {
		t.Errorf("Expected cached token %s, but got %s", token, cachedToken)
	}
}

func TestAuthorizationHeaderNoCreds(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	bp := BackendProxy{URL: origin.URL}
	auth := NewTokenAuth("", "")
	_, err := auth.AuthorizationHeader(&bp, "foobar")

	if !strings.Contains(err.Error(), "username and password are not specified") {
		t.Errorf("Unexpected error %s", err.Error())
	}
}

func TestAuthorizationHeaderBadRegistryName(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	origin.URL = "http://bad registry"

	bp := BackendProxy{URL: origin.URL}
	auth := NewTokenAuth("test", "test")
	_, err := auth.AuthorizationHeader(&bp, "foobar")

	if !strings.Contains(err.Error(), "unable parse registry url") {
		t.Errorf("Unexpected error %s", err.Error())
	}
}

func TestAuthorizationHeaderNoChallenge(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	bp := BackendProxy{URL: origin.URL}
	auth := NewTokenAuth("test", "test")
	_, err := auth.AuthorizationHeader( &bp, "foobar")

	if !strings.Contains(err.Error(), "no auth challenge presented by backend registry") {
		t.Errorf("Unexpected error %s", err.Error())
	}
}

func TestAuthorizationHeaderBadChallenge(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer origin.Close()

	bp := BackendProxy{URL: origin.URL}
	auth := NewTokenAuth("test", "test")
	_, err := auth.AuthorizationHeader(&bp, "foobar")

	if !strings.Contains(err.Error(), "unable to get auth challenge from backend registry") {
		t.Errorf("Unexpected error %s", err.Error())
	}
}

func TestAuthorizationHeaderBadRealm(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge := `Bearer realm="http://bad realm/v2/auth",service="service",scope="scope"`
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer origin.Close()

	bp := BackendProxy{URL: origin.URL}
	auth := NewTokenAuth("test", "test")
	_, err := auth.AuthorizationHeader(&bp, "foobar")

	if !strings.Contains(err.Error(), "unable parse token realm url") {
		t.Errorf("Unexpected error %s", err.Error())
	}
}

func TestAuthorizationHeaderBadTokenEndpoint(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge := `Bearer realm="http://fakebackend/v2/auth",service="service",scope="scope"`
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer origin.Close()

	bp := BackendProxy{URL: origin.URL}
	auth := NewTokenAuth("test", "test")
	_, err := auth.AuthorizationHeader(&bp, "foobar")

	if !strings.Contains(err.Error(), "unable to request token from backend registry") {
		t.Errorf("Unexpected error %s", err.Error())
	}
}

func TestAuthorizationHeaderBadTokenResponse(t *testing.T) {
	token := tests.GenToken(time.Now(), "quay")
	origin := originAuthServer(token)
	defer origin.Close()

	bp := BackendProxy{URL: origin.URL}
	auth := NewTokenAuth("testerror", "test")
	_, err := auth.AuthorizationHeader(&bp, "foobar")

	if !strings.Contains(err.Error(), "invalid status received from token endpoint") {
		t.Errorf("Unexpected error %s", err.Error())
	}
}

func TestAuthorizationHeaderCachedToken(t *testing.T) {
	token := tests.GenToken(time.Now(), "quay")
	utils.CacheClient = &tests.MockCache{}
	utils.CacheClient.Set("foobar", token, 1)

	bp := BackendProxy{}
	auth := NewTokenAuth("test", "test")
	got, _ := auth.AuthorizationHeader(&bp, "foobar")

	if  got != "Bearer " + token {
		t.Errorf("Expected token %s, but got %s", token, got)
	}
}
