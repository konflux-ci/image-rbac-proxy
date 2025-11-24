package handlers

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/sirupsen/logrus"

	"image-rbac-proxy/pkg/utils"
)

var BackendRegistry *BackendProxy

// BackendProxy is a ReverseProxy pointer for the backend registry
type BackendProxy struct {
	URL       string
	Proxy     *httputil.ReverseProxy
	Auth      BackendAuth
}

// BackendAuth provides methods to authenticate to a backend registry
type BackendAuth interface {
	AuthorizationHeader(*BackendProxy, string) (string, error)
}

// RegistryHandler is the handler that enforces authentication
func RegistryHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v2/" {
		return
	}

	bp := BackendRegistry
	repoName := utils.RepoFromPath(r.URL.Path)

	header, err := bp.Auth.AuthorizationHeader(bp, repoName)
	if err != nil {
		logrus.Errorf("Unable to fetch credentials for registry backend: %s", err)
		utils.ErrorHTTPResponse(w, utils.Unavailable, "Server error encountered while fetching credentials")
		return
	}
	r.Header.Set("Authorization", header)

	bp.ProxyHandler(w, r)
}

// ProxyHandler simply proxies the request to the backend
func (bp *BackendProxy) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	if bp.Proxy == nil {
		bp.Initialize(r)
	}

	bp.Proxy.ServeHTTP(w, r)
}

// Initialize sets up the transport and client for the reverse proxy
func (bp *BackendProxy) Initialize(r *http.Request) {
	// create the reverse proxy
	bp.Proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Host = bp.GetURL().Host
			req.URL.Scheme = bp.GetURL().Scheme
			req.Host = bp.GetURL().Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logrus.WithError(err).Error("Backend request failed")
			utils.ErrorHTTPResponse(w, utils.Unavailable, "Server error encountered while handling request")
			return
		},
	}
}

// GetURL returns a URL from the configured string
func (bp *BackendProxy) GetURL() *url.URL {
	u, _ := url.Parse(bp.URL)
	return u
}
