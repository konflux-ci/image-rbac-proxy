package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"image-rbac-proxy/pkg/utils"
)

// AuthHandler issues auth token for podman
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	// Use the password as the token
	_, token, ok := r.BasicAuth()
	if !ok {
		utils.ErrorHTTPResponse(w, utils.Unauthorized, "No basic auth credentials provided")
		return
	}

	username := ""
	claims := utils.TokenClaims(token)
	if claims != nil {
		if claims.Issuer == os.Getenv("DEX_URL") {
			// Verify user's token issued by dex
			username, _ = VerifyIDToken(token)
		} else {
			// Verify serive account's token issued by OpenShift
			username = VerifyServiceAccount(token)
		}
	}
	if username != "" {
		logrus.Printf("Verified user: %s", username)
		data := map[string]string{
			"token": token,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	} else {
		utils.ErrorHTTPResponse(w, utils.Unauthorized, "Token is invalid or expired")
	}
}

func VerifyServiceAccount(token string) string {
	config := &rest.Config{
		Host:        os.Getenv("CLUSTER_URL"),
		BearerToken: os.Getenv("OAUTH_TOKEN"),
	}

	// Create a Kubernetes client
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		logrus.Errorf("Error creating Kubernetes client: %s", err)
		return ""
	}

	// Verify service account token
	tr := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     token,
		},
	}
	response, err := client.AuthenticationV1().TokenReviews().Create(context.Background(), tr, metav1.CreateOptions{})

	if err != nil {
		logrus.Errorf("Token review failed with error: %s", err)
		return ""
	}

	if !response.Status.Authenticated {
		if response.Status.Error != "" {
			logrus.Errorf("Token is not authenticated: %s", response.Status.Error)
		}
		return ""
	}

	return response.Status.User.Username
}
