package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sirupsen/logrus"

	"image-rbac-proxy/pkg/utils"
)

// TokenAuth contains credentials to be exchanged for a token
type TokenAuth struct {
	username    string
	password    string
	tokenClient *http.Client
}

type tokenResponse struct {
	Token       string
}

// NewTokenAuth constructs a TokenAuth struct
func NewTokenAuth(user, pass string) *TokenAuth {
	return &TokenAuth{username: user, password: pass}
}

// AuthorizationHeader returns an Authorization header to be sent upstream
func (a *TokenAuth) AuthorizationHeader(bp *BackendProxy, repo string) (string, error) {
	if a == nil {
		return "", nil
	}

	if len(a.username) == 0 || len(a.password) == 0 {
		return "", errors.New("username and password are not specified")
	}

	var rawToken string
	// Check cache for token
	if utils.CacheClient != nil {
		err := utils.CacheClient.Get(repo, &rawToken)
		if err != nil {
			logrus.Error(err)
		}
	}

	if len(rawToken) == 0 || !utils.IsValidToken(rawToken) {
		t, err := a.requestToken(bp.URL, repo)
		if err != nil {
			return "", fmt.Errorf("unable to request access token for repo %s: %s", repo, err)
		}
		rawToken = t
	}

	// Return the token
	return "Bearer " + rawToken, nil
}

func (a *TokenAuth) requestToken(registryURL string, repo string) (string, error) {
	// Initialize HTTP client if needed
	if a.tokenClient == nil {
		a.tokenClient = &http.Client{}
	}

	// Obtain auth challenge from the backend registry
	registryAsURL, err := url.Parse(registryURL)
	if err != nil {
		return "", fmt.Errorf("unable parse registry url: %s", err)
	}

	registry, err := name.NewRegistry(registryAsURL.Host)
	if err != nil {
		return "", fmt.Errorf("unable create new registry: %s", err)
	}

	challenge, err := transport.Ping(context.Background(), registry, a.tokenClient.Transport)
	if err != nil {
		return "", fmt.Errorf("unable to get auth challenge from backend registry: %s", err)
	}

	if len(challenge.Parameters) == 0 {
		return "", errors.New("no auth challenge presented by backend registry")
	}

	// Build token request
	tokenURL, err := url.Parse(challenge.Parameters["realm"])
	if err != nil {
		return "", fmt.Errorf("unable parse token realm url: %s", err)
	}

	params := url.Values{}
	params.Add("service", challenge.Parameters["service"])
	params.Add("client_id", "image-rbac-proxy")
	params.Add("scope", fmt.Sprintf("repository:%s:%s", repo, transport.PullScope))
	tokenURL.RawQuery = params.Encode()

	// Get token
	tokenReq, _ := http.NewRequest("GET", tokenURL.String(), nil)
	tokenReq.SetBasicAuth(a.username, a.password)
	resp, err := a.tokenClient.Do(tokenReq)
	if err != nil {
		return "", fmt.Errorf("unable to request token from backend registry: %s", err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read body from token response: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("invalid status received from token endpoint: %s", body)
	}

	var tokenResp tokenResponse
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		logrus.Error(err)
	}

	if len(tokenResp.Token) == 0 {
		return "", fmt.Errorf("no token received in response")
	}
	token := tokenResp.Token

	// Store the token
	if utils.CacheClient != nil {
		claims := utils.TokenClaims(token)
		ttl := claims.ExpiresAt - time.Now().Unix() - 30
		err = utils.CacheClient.Set(repo, token, int(ttl))
		if err != nil {
			logrus.Error(err)
		}
	}
	return token, nil
}
