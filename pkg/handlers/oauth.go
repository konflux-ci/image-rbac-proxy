package handlers

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"image-rbac-proxy/pkg/utils"
)

const (
	oauthSessionCookieName        = "oauth_session"
	oauthSessionCacheKeyPrefix    = "oauth_session:"
	pendingOAuthSessionTTLSeconds = 3 * 60 // 3 minutes
)

type oauthSession struct {
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
}

func newProvider() *oidc.Provider {
	provider, err := oidc.NewProvider(context.Background(), os.Getenv("DEX_URL"))
	if err != nil {
		logrus.Errorf("Error oidc provider: %s", err)
		return nil
	}
	return provider
}

func getOauthConfig() oauth2.Config {
	provider := newProvider()
	if provider == nil {
		return oauth2.Config{}
	}

	oauth2Config := oauth2.Config{
		ClientID:     os.Getenv("DEX_CLIENT_ID"),
		ClientSecret: os.Getenv("DEX_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("PROXY_URL") + "/oauth/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "groups"},
	}

	return oauth2Config
}

func newRandomValue() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(value), nil
}

// OauthHandler redirects user to dex
func OauthHandler(w http.ResponseWriter, r *http.Request) {
	oauth2Config := getOauthConfig()
	if oauth2Config.ClientID == "" {
		utils.ErrorHTTPResponse(w, utils.Unavailable, "Error getting oauth config")
		return
	}

	state, err := newRandomValue()
	if err != nil {
		utils.ErrorHTTPResponse(w, utils.Unavailable, "Error generating state")
		return
	}

	sessionID, err := newRandomValue()
	if err != nil {
		utils.ErrorHTTPResponse(w, utils.Unavailable, "Error generating session")
		return
	}

	if utils.CacheClient == nil {
		utils.ErrorHTTPResponse(w, utils.Unavailable, "OAuth session cache unavailable")
		return
	}

	// Generate a one-time PKCE secret for this authorization request.
	codeVerifier := oauth2.GenerateVerifier()

	// Store the OAuth state and PKCE verifier server-side; the browser receives only an opaque session ID.
	session := oauthSession{
		State:        state,
		CodeVerifier: codeVerifier,
	}

	cacheKey := oauthSessionCacheKeyPrefix + sessionID

	if err := utils.CacheClient.Set(
		cacheKey,
		session,
		pendingOAuthSessionTTLSeconds,
	); err != nil {
		logrus.Errorf("Error storing OAuth session: %s", err)
		utils.ErrorHTTPResponse(w, utils.Unavailable, "Error starting OAuth session")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     oauthSessionCookieName,
		Value:    sessionID,
		Path:     "/oauth/callback",
		MaxAge:   pendingOAuthSessionTTLSeconds,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Send only the verifier's SHA-256 challenge to Dex.
	authorizationURL := oauth2Config.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(codeVerifier),
	)

	http.Redirect(w, r, authorizationURL, http.StatusFound)
}

// OauthCallbackHandler issues oauth token
func OauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie(oauthSessionCookieName)
	if err != nil || sessionCookie.Value == "" {
		utils.ErrorHTTPResponse(w, utils.BadRequest, "Invalid OAuth session")
		return
	}

	if utils.CacheClient == nil {
		utils.ErrorHTTPResponse(
			w,
			utils.Unavailable,
			"OAuth session cache unavailable",
		)
		return
	}

	cacheKey := oauthSessionCacheKeyPrefix + sessionCookie.Value

	var session oauthSession
	if err := utils.CacheClient.Get(cacheKey, &session); err != nil {
		logrus.Errorf("Error retrieving OAuth session: %s", err)
		utils.ErrorHTTPResponse(w, utils.BadRequest, "Invalid or expired OAuth session")
		return
	}

	returnedState := r.URL.Query().Get("state")

	// Ensure the callback belongs to the login session started by this browser.
	if subtle.ConstantTimeCompare(
		[]byte(returnedState),
		[]byte(session.State),
	) != 1 {
		utils.ErrorHTTPResponse(w, utils.BadRequest, "Invalid OAuth state")
		return
	}

	// Consume the session before Dex; concurrent callbacks fail when one deletes it first.
	if err := utils.CacheClient.Delete(cacheKey); err != nil {
		logrus.Errorf("Error deleting OAuth session: %s", err)
		utils.ErrorHTTPResponse(w, utils.BadRequest, "Invalid or expired OAuth session")
		return
	}

	// Remove the browser-side session ID now that the server-side session is consumed.
	http.SetCookie(w, &http.Cookie{
		Name:     oauthSessionCookieName,
		Value:    "",
		Path:     "/oauth/callback",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	oauth2Config := getOauthConfig()
	if oauth2Config.ClientID == "" {
		utils.ErrorHTTPResponse(w, utils.Unavailable, "Error getting oauth config")
		return
	}

	// Prove this proxy started the login by sending the cached PKCE verifier.
	oauth2Token, err := oauth2Config.Exchange(
		context.Background(),
		r.URL.Query().Get("code"),
		oauth2.VerifierOption(session.CodeVerifier),
	)
	if err != nil {
		utils.ErrorHTTPResponse(w, utils.Unavailable, "Error getting token from dex")
		return
	}

	// Extract the ID Token from OAuth2 token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		utils.ErrorHTTPResponse(w, utils.Unavailable, "Missing id_token")
		return
	}

	_, _ = w.Write([]byte(rawIDToken)) // #nosec G705 -- OAuth callback intentionally returns the raw ID token
}

func VerifyIDToken(token string) (string, []string) {
	provider := newProvider()
	if provider == nil {
		return "", []string{}
	}
	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: os.Getenv("DEX_CLIENT_ID")})
	idToken, err := idTokenVerifier.Verify(context.Background(), token)
	if err != nil {
		logrus.Errorf("Error verifying token: %s", err)
		return "", []string{}
	}

	// Extract name
	var claims struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		logrus.Errorf("Error extracting claims from token: %s", err)
		return "", []string{}
	}
	return claims.Email, claims.Groups
}
