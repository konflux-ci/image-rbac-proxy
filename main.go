package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"image-rbac-proxy/pkg/handlers"
	"image-rbac-proxy/pkg/utils"
	mw "image-rbac-proxy/pkg/middleware"
)

func main() {
	// Setup logging
	logrus.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339Nano})
	level, _ := logrus.ParseLevel("info")
	logrus.SetLevel(level)

	// Initializa memcache
	utils.InitCacheClient(strings.Split(os.Getenv("MEMCACHE_SERVERS"), ","))

	// Setup backend from config
	initBackendProxy()

	// Setup handlers
	proxy := http.NewServeMux()
	registryHandler := http.HandlerFunc(handlers.RegistryHandler)
	chainedHandler := mw.Authz(registryHandler)
	proxy.Handle("/v2/", chainedHandler)
	proxy.HandleFunc("/_ping", handlers.PingHandler)
	proxy.HandleFunc("/auth", handlers.AuthHandler)
	proxy.HandleFunc("/oauth", handlers.OauthHandler)
	proxy.HandleFunc("/oauth/callback", handlers.OauthCallbackHandler)

	// Configure server based on settings
	bind := fmt.Sprintf("0.0.0.0:4000")
	lw := logrus.StandardLogger().Writer()
	defer lw.Close()
	srv := &http.Server{
		Addr:         bind,
		Handler:      proxy,
		ErrorLog:     log.New(lw, "", 0),
	}

	// Start server
	logrus.Printf("Listening on %s", bind)
	logrus.Fatal(srv.ListenAndServeTLS("/certs/tls.crt", "/certs/tls.key"))
}

func initBackendProxy() {
	url := os.Getenv("BACKEND_URL")
	username := os.Getenv("QUAY_USERNAME")
	password := os.Getenv("QUAY_PASSWORD")
		
	var auth handlers.BackendAuth
	auth = handlers.NewTokenAuth(username, password)
	logrus.Printf("Adding registry backend with URL %s", url)
	handlers.BackendRegistry = &handlers.BackendProxy{URL: url, Auth: auth}
}
