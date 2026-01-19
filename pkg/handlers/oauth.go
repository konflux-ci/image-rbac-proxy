package handlers

import (
	"context"
	"os"
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"image-rbac-proxy/pkg/utils"
)

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

func newState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// OauthHandler redirects user to dex
func OauthHandler(w http.ResponseWriter, r *http.Request) {
	oauth2Config := getOauthConfig()
	state := newState()
	if oauth2Config.ClientID != "" {
		http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
	} else {
		utils.ErrorHTTPResponse(w, utils.Unavailable, "Error getting oauth config")
		return
	}
}

// OauthCallbackHandler issues oauth token
func OauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	oauth2Config := getOauthConfig()
	if oauth2Config.ClientID == "" {
		utils.ErrorHTTPResponse(w, utils.Unavailable, "Error getting oauth config")
		return
	}

	// Exchange code for token
	oauth2Token, err := oauth2Config.Exchange(context.Background(), r.URL.Query().Get("code"))
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

	w.Write([]byte(rawIDToken))
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
	idToken.Claims(&claims)
	return claims.Email, claims.Groups
}
