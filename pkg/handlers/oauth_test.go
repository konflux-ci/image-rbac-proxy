package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"image-rbac-proxy/pkg/tests"
	"image-rbac-proxy/pkg/utils"

	"golang.org/x/oauth2"
)

func TestOauthHandler(t *testing.T) {
	mockCache := &tests.MockCache{}
	previousCache := utils.CacheClient
	utils.CacheClient = mockCache
	t.Cleanup(func() {
		utils.CacheClient = previousCache
	})

	r := httptest.NewRequest("GET", "/oauth", nil)
	rr := httptest.NewRecorder()
	mockServer := tests.NewMockOIDCServer()
	defer mockServer.Close()

	t.Setenv("DEX_URL", mockServer.Server.URL)
	t.Setenv("DEX_CLIENT_ID", "test-client")
	t.Setenv("DEX_CLIENT_SECRET", "test-secret")
	t.Setenv("PROXY_URL", "https://fakeproxy")

	OauthHandler(rr, r)

	if rr.Code != http.StatusFound {
		t.Fatalf("Expected auth %d, but got %d", http.StatusFound, rr.Code)
	}

	location := rr.Header().Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Invalid redirect URL: %v", err)
	}

	redirectState := redirectURL.Query().Get("state")
	if redirectState == "" {
		t.Fatal("Expected state in redirect URL")
	}

	codeChallenge := redirectURL.Query().Get("code_challenge")
	if codeChallenge == "" {
		t.Fatal("Expected PKCE code challenge in redirect URL")
	}

	challengeMethod := redirectURL.Query().Get("code_challenge_method")
	if challengeMethod != "S256" {
		t.Errorf(
			"Expected PKCE challenge method S256, got %q",
			challengeMethod,
		)
	}

	var sessionCookie *http.Cookie
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == oauthSessionCookieName {
			sessionCookie = cookie
			break
		}
	}

	if sessionCookie == nil {
		t.Fatal("Expected OAuth session cookie")
	}

	if sessionCookie.Value == "" {
		t.Fatal("Expected session ID in OAuth session cookie")
	}

	if !sessionCookie.Secure {
		t.Error("Expected OAuth session cookie to be Secure")
	}

	if !sessionCookie.HttpOnly {
		t.Error("Expected OAuth session cookie to be HttpOnly")
	}

	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("Expected SameSite=Lax, got %v", sessionCookie.SameSite)
	}

	if sessionCookie.Path != "/oauth/callback" {
		t.Errorf("Expected callback cookie path, got %q", sessionCookie.Path)
	}

	if sessionCookie.MaxAge != pendingOAuthSessionTTLSeconds {
		t.Errorf(
			"Expected cookie MaxAge %d, got %d",
			pendingOAuthSessionTTLSeconds,
			sessionCookie.MaxAge,
		)
	}

	var cachedSession struct {
		State        string `json:"state"`
		CodeVerifier string `json:"code_verifier"`
	}
	cacheKey := oauthSessionCacheKeyPrefix + sessionCookie.Value
	if err := mockCache.Get(cacheKey, &cachedSession); err != nil {
		t.Fatalf("Expected cached OAuth session: %v", err)
	}

	if cachedSession.State != redirectState {
		t.Errorf(
			"Expected cached state %q to match redirect state %q",
			cachedSession.State,
			redirectState,
		)
	}

	if cachedSession.CodeVerifier == "" {
		t.Fatal("Expected PKCE verifier in cached OAuth session")
	}

	expectedChallenge := oauth2.S256ChallengeFromVerifier(
		cachedSession.CodeVerifier,
	)
	if codeChallenge != expectedChallenge {
		t.Errorf(
			"Expected redirect challenge %q to match cached verifier challenge %q",
			codeChallenge,
			expectedChallenge,
		)
	}
}

func TestOauthCallbackHandlerRejectsMissingSessionCookie(t *testing.T) {
	r := httptest.NewRequest(
		"GET",
		"/oauth/callback?code=fakecode&state=test-state",
		nil,
	)
	rr := httptest.NewRecorder()

	mockServer := tests.NewMockOIDCServer()
	defer mockServer.Close()

	t.Setenv("DEX_URL", mockServer.Server.URL)
	t.Setenv("DEX_CLIENT_ID", "test-client")
	t.Setenv("DEX_CLIENT_SECRET", "test-secret")
	t.Setenv("PROXY_URL", "https://fakeproxy")

	OauthCallbackHandler(rr, r)

	if rr.Code != http.StatusBadRequest {
		t.Errorf(
			"Expected missing session cookie to return %d, got %d",
			http.StatusBadRequest,
			rr.Code,
		)
	}

	if rr.Body.String() == "mock-id-token" {
		t.Error("Expected callback without session cookie to be rejected")
	}
}

func TestOauthCallbackHandlerRejectsMissingCachedSession(t *testing.T) {
	mockCache := &tests.MockCache{}
	previousCache := utils.CacheClient
	utils.CacheClient = mockCache
	t.Cleanup(func() {
		utils.CacheClient = previousCache
	})

	r := httptest.NewRequest(
		"GET",
		"/oauth/callback?code=fakecode&state=test-state",
		nil,
	)
	r.AddCookie(&http.Cookie{
		Name:  oauthSessionCookieName,
		Value: "missing-session",
	})

	rr := httptest.NewRecorder()

	mockServer := tests.NewMockOIDCServer()
	defer mockServer.Close()

	t.Setenv("DEX_URL", mockServer.Server.URL)
	t.Setenv("DEX_CLIENT_ID", "test-client")
	t.Setenv("DEX_CLIENT_SECRET", "test-secret")
	t.Setenv("PROXY_URL", "https://fakeproxy")

	OauthCallbackHandler(rr, r)

	if rr.Code != http.StatusBadRequest {
		t.Errorf(
			"Expected missing cached session to return %d, got %d",
			http.StatusBadRequest,
			rr.Code,
		)
	}

	if rr.Body.String() == "mock-id-token" {
		t.Error("Expected callback with missing cached session to be rejected")
	}
}

func TestOauthCallbackHandlerRejectsMismatchedState(t *testing.T) {
	mockCache := &tests.MockCache{}
	previousCache := utils.CacheClient
	utils.CacheClient = mockCache
	t.Cleanup(func() {
		utils.CacheClient = previousCache
	})

	const sessionID = "test-session"

	err := mockCache.Set(
		oauthSessionCacheKeyPrefix+sessionID,
		oauthSession{State: "expected-state"},
		pendingOAuthSessionTTLSeconds,
	)
	if err != nil {
		t.Fatalf("Failed to prepare cached OAuth session: %v", err)
	}

	r := httptest.NewRequest(
		"GET",
		"/oauth/callback?code=fakecode&state=wrong-state",
		nil,
	)
	r.AddCookie(&http.Cookie{
		Name:  oauthSessionCookieName,
		Value: sessionID,
	})

	rr := httptest.NewRecorder()

	mockServer := tests.NewMockOIDCServer()
	defer mockServer.Close()

	t.Setenv("DEX_URL", mockServer.Server.URL)
	t.Setenv("DEX_CLIENT_ID", "test-client")
	t.Setenv("DEX_CLIENT_SECRET", "test-secret")
	t.Setenv("PROXY_URL", "https://fakeproxy")

	OauthCallbackHandler(rr, r)

	if rr.Code != http.StatusBadRequest {
		t.Errorf(
			"Expected mismatched state to return %d, got %d",
			http.StatusBadRequest,
			rr.Code,
		)
	}

	if rr.Body.String() == "mock-id-token" {
		t.Error("Expected callback with mismatched state to be rejected")
	}
}

func TestOauthCallbackHandlerRejectsMissingState(t *testing.T) {
	mockCache := &tests.MockCache{}
	previousCache := utils.CacheClient
	utils.CacheClient = mockCache
	t.Cleanup(func() {
		utils.CacheClient = previousCache
	})

	const sessionID = "test-session"

	err := mockCache.Set(
		oauthSessionCacheKeyPrefix+sessionID,
		oauthSession{State: "expected-state"},
		pendingOAuthSessionTTLSeconds,
	)
	if err != nil {
		t.Fatalf("Failed to prepare cached OAuth session: %v", err)
	}

	r := httptest.NewRequest(
		"GET",
		"/oauth/callback?code=fakecode",
		nil,
	)
	r.AddCookie(&http.Cookie{
		Name:  oauthSessionCookieName,
		Value: sessionID,
	})

	rr := httptest.NewRecorder()

	OauthCallbackHandler(rr, r)

	if rr.Code != http.StatusBadRequest {
		t.Errorf(
			"Expected missing state to return %d, got %d",
			http.StatusBadRequest,
			rr.Code,
		)
	}
}

func TestOauthCallbackHandlerAcceptsMatchingState(t *testing.T) {
	mockCache := &tests.MockCache{}
	previousCache := utils.CacheClient
	utils.CacheClient = mockCache
	t.Cleanup(func() {
		utils.CacheClient = previousCache
	})

	const sessionID = "test-session"
	const state = "expected-state"

	err := mockCache.Set(
		oauthSessionCacheKeyPrefix+sessionID,
		oauthSession{
			State:        state,
			CodeVerifier: oauth2.GenerateVerifier(),
		},
		pendingOAuthSessionTTLSeconds,
	)
	if err != nil {
		t.Fatalf("Failed to prepare cached OAuth session: %v", err)
	}

	r := httptest.NewRequest(
		"GET",
		"/oauth/callback?code=fakecode&state="+state,
		nil,
	)
	r.AddCookie(&http.Cookie{
		Name:  oauthSessionCookieName,
		Value: sessionID,
	})

	rr := httptest.NewRecorder()

	mockServer := tests.NewMockOIDCServer()
	defer mockServer.Close()

	t.Setenv("DEX_URL", mockServer.Server.URL)
	t.Setenv("DEX_CLIENT_ID", "test-client")
	t.Setenv("DEX_CLIENT_SECRET", "test-secret")
	t.Setenv("PROXY_URL", "https://fakeproxy")

	OauthCallbackHandler(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf(
			"Expected matching state to return %d, got %d",
			http.StatusOK,
			rr.Code,
		)
	}

	if rr.Body.String() != "mock-id-token" {
		t.Errorf("Incorrect token in response: %s", rr.Body.String())
	}
}

func TestOauthCallbackHandlerClearsSessionCookie(t *testing.T) {
	mockCache := &tests.MockCache{}
	previousCache := utils.CacheClient
	utils.CacheClient = mockCache
	t.Cleanup(func() {
		utils.CacheClient = previousCache
	})

	const sessionID = "test-session"
	const state = "expected-state"

	err := mockCache.Set(
		oauthSessionCacheKeyPrefix+sessionID,
		oauthSession{
			State:        state,
			CodeVerifier: oauth2.GenerateVerifier(),
		},
		pendingOAuthSessionTTLSeconds,
	)
	if err != nil {
		t.Fatalf("Failed to prepare cached OAuth session: %v", err)
	}

	r := httptest.NewRequest(
		"GET",
		"/oauth/callback?code=fakecode&state="+state,
		nil,
	)
	r.AddCookie(&http.Cookie{
		Name:  oauthSessionCookieName,
		Value: sessionID,
	})

	rr := httptest.NewRecorder()

	mockServer := tests.NewMockOIDCServer()
	defer mockServer.Close()

	t.Setenv("DEX_URL", mockServer.Server.URL)
	t.Setenv("DEX_CLIENT_ID", "test-client")
	t.Setenv("DEX_CLIENT_SECRET", "test-secret")
	t.Setenv("PROXY_URL", "https://fakeproxy")

	OauthCallbackHandler(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf(
			"Expected callback to return %d, got %d",
			http.StatusOK,
			rr.Code,
		)
	}

	var clearedCookie *http.Cookie
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == oauthSessionCookieName {
			clearedCookie = cookie
			break
		}
	}

	if clearedCookie == nil {
		t.Fatal("Expected callback to clear OAuth session cookie")
	}

	if clearedCookie.Value != "" {
		t.Errorf("Expected cleared cookie value, got %q", clearedCookie.Value)
	}

	if clearedCookie.MaxAge >= 0 {
		t.Errorf("Expected expired cookie MaxAge, got %d", clearedCookie.MaxAge)
	}

	if clearedCookie.Path != "/oauth/callback" {
		t.Errorf("Expected callback cookie path, got %q", clearedCookie.Path)
	}
}

func TestOauthCallbackHandlerRejectsReplayedSession(t *testing.T) {
	mockCache := &tests.MockCache{}
	previousCache := utils.CacheClient
	utils.CacheClient = mockCache
	t.Cleanup(func() {
		utils.CacheClient = previousCache
	})

	const sessionID = "test-session"
	const state = "expected-state"

	err := mockCache.Set(
		oauthSessionCacheKeyPrefix+sessionID,
		oauthSession{
			State:        state,
			CodeVerifier: oauth2.GenerateVerifier(),
		},
		pendingOAuthSessionTTLSeconds,
	)
	if err != nil {
		t.Fatalf("Failed to prepare cached OAuth session: %v", err)
	}

	mockServer := tests.NewMockOIDCServer()
	defer mockServer.Close()

	t.Setenv("DEX_URL", mockServer.Server.URL)
	t.Setenv("DEX_CLIENT_ID", "test-client")
	t.Setenv("DEX_CLIENT_SECRET", "test-secret")
	t.Setenv("PROXY_URL", "https://fakeproxy")

	firstRequest := httptest.NewRequest(
		"GET",
		"/oauth/callback?code=fakecode&state="+state,
		nil,
	)
	firstRequest.AddCookie(&http.Cookie{
		Name:  oauthSessionCookieName,
		Value: sessionID,
	})

	firstResponse := httptest.NewRecorder()
	OauthCallbackHandler(firstResponse, firstRequest)

	if firstResponse.Code != http.StatusOK {
		t.Fatalf(
			"Expected first callback to return %d, got %d",
			http.StatusOK,
			firstResponse.Code,
		)
	}

	replayRequest := httptest.NewRequest(
		"GET",
		"/oauth/callback?code=fakecode&state="+state,
		nil,
	)
	replayRequest.AddCookie(&http.Cookie{
		Name:  oauthSessionCookieName,
		Value: sessionID,
	})

	replayResponse := httptest.NewRecorder()
	OauthCallbackHandler(replayResponse, replayRequest)

	if replayResponse.Code != http.StatusBadRequest {
		t.Errorf(
			"Expected replayed session to return %d, got %d",
			http.StatusBadRequest,
			replayResponse.Code,
		)
	}
}

func TestVerifyIDToken(t *testing.T) {
	mockServer := tests.NewMockOIDCServer()
	defer mockServer.Close()
	t.Setenv("DEX_URL", mockServer.Server.URL)
	t.Setenv("DEX_CLIENT_ID", "test-client")
	token, _ := mockServer.GenIDToken("test-client", "user1", []string{"group1", "group2"})

	email, groups := VerifyIDToken(token)

	if email != "user1" {
		t.Errorf("Incorrect email: %s", email)
	}
	if !slices.Equal(groups, []string{"group1", "group2"}) {
		t.Errorf("Incorrect groups: %s", groups)
	}
}

func TestOauthCallbackHandlerUsesPKCEVerifier(t *testing.T) {
	mockCache := &tests.MockCache{}
	previousCache := utils.CacheClient
	utils.CacheClient = mockCache
	t.Cleanup(func() {
		utils.CacheClient = previousCache
	})

	const sessionID = "test-session"
	const state = "expected-state"
	codeVerifier := oauth2.GenerateVerifier()

	err := mockCache.Set(
		oauthSessionCacheKeyPrefix+sessionID,
		oauthSession{
			State:        state,
			CodeVerifier: codeVerifier,
		},
		pendingOAuthSessionTTLSeconds,
	)
	if err != nil {
		t.Fatalf("Failed to prepare cached OAuth session: %v", err)
	}

	mockServer := tests.NewMockOIDCServerWithPKCE(codeVerifier)
	defer mockServer.Close()

	t.Setenv("DEX_URL", mockServer.Server.URL)
	t.Setenv("DEX_CLIENT_ID", "test-client")
	t.Setenv("DEX_CLIENT_SECRET", "test-secret")
	t.Setenv("PROXY_URL", "https://fakeproxy")

	r := httptest.NewRequest(
		"GET",
		"/oauth/callback?code=fakecode&state="+state,
		nil,
	)
	r.AddCookie(&http.Cookie{
		Name:  oauthSessionCookieName,
		Value: sessionID,
	})

	rr := httptest.NewRecorder()
	OauthCallbackHandler(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf(
			"Expected PKCE token exchange to return %d, got %d",
			http.StatusOK,
			rr.Code,
		)
	}
}
