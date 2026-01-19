package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
)

// MockOIDCServer creates a mock OIDC/OAuth2 server for testing
type MockOIDCServer struct {
	Server          *httptest.Server
	TokenResponse   *oauth2.Token
	IDToken         string
        privateKey      *rsa.PrivateKey
        publicKey       *rsa.PublicKey
}

// NewMockOIDCServer creates a new mock OIDC server
func NewMockOIDCServer() *MockOIDCServer {
	// Generate RSA key pair for signing tokens
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	mock := &MockOIDCServer{
		IDToken: "mock-id-token",
		TokenResponse: &oauth2.Token{
			AccessToken:  "mock-access-token",
		},
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}

	mux := http.NewServeMux()

	// OIDC discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]interface{}{
			"issuer":                 mock.Server.URL,
			"authorization_endpoint": mock.Server.URL + "/auth",
			"token_endpoint":         mock.Server.URL + "/token",
			"jwks_uri":               mock.Server.URL + "/keys",
			"userinfo_endpoint":      mock.Server.URL + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	})

	// Token endpoint
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"access_token":  mock.TokenResponse.AccessToken,
			"id_token":      mock.IDToken,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// JWKS endpoint (for token verification)
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		// Encode the public key components
		nBytes := mock.publicKey.N.Bytes()
		eBytes := big.NewInt(int64(mock.publicKey.E)).Bytes()

		keys := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"kid": "mock-key",
					"use": "sig",
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(nBytes),
					"e":   base64.RawURLEncoding.EncodeToString(eBytes),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keys)
	})

	mock.Server = httptest.NewServer(mux)
	return mock
}

// Close shuts down the mock server
func (m *MockOIDCServer) Close() {
	m.Server.Close()
}

// GenIDToken creates a valid signed JWT token for testing
func (m *MockOIDCServer) GenIDToken(clientID, email string, groups []string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":    m.Server.URL,
		"sub":    "test",
		"aud":    clientID,
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"email":  email,
		"groups": groups,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "mock-key"

	return token.SignedString(m.privateKey)
}
