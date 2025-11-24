package handlers

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// PingHandler simply responds with a pong
func PingHandler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("pong"))
	if err != nil {
		logrus.Errorf("Ping failed with error: %s", err)
	}
}
