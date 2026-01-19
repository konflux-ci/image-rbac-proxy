package middleware

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"image-rbac-proxy/pkg/handlers"
	"image-rbac-proxy/pkg/utils"
)

// Auth is middleware to extract a token from a request and verify if it can access repo
func Authz(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Enforce auth if needed
		if strings.HasPrefix(r.URL.Path, "/v2") {
			logrus.Printf("%s %s", r.Method, r.URL.Path)
			token := getToken(r)

			// Issue an auth challenge and error if no token
			if token == "" {
				challenge := fmt.Sprintf("Bearer realm=\"%s/auth\"", os.Getenv("PROXY_URL"))
				w.Header().Add("WWW-Authenticate", challenge)
				utils.ErrorHTTPResponse(w, utils.Unauthorized, "Access to the requested resource is not authorized")
				return
			} else {
				if r.URL.Path == "/v2/" {
					return
				}

				repoName := utils.RepoFromPath(r.URL.Path)
				if repoName == "" {
					utils.ErrorHTTPResponse(w, utils.Unauthorized, "Proxy has no access to the requested resource")
					return
				}
				quay_namespace := strings.Split(repoName, "/")[0]
				ocp_namespace := strings.Split(repoName, "/")[1]
				if quay_namespace != os.Getenv("BACKEND_NAMESPACE") {
					utils.ErrorHTTPResponse(w, utils.Unauthorized, "Proxy has no access to " + quay_namespace)
					return
				}

				// Get username from token
				var username string
				var groups []string
				claims := utils.TokenClaims(token)
				if claims != nil {
					if claims.Issuer == os.Getenv("DEX_URL") {
						// Verify user's token issued by dex
						username, groups = handlers.VerifyIDToken(token)
					} else {
						// Verify serive account's token issued by OpenShift
						username = handlers.VerifyServiceAccount(token)
					}
				}
				if username == "" {
					utils.ErrorHTTPResponse(w, utils.Unauthorized, "Token is invalid or expired")
					return
				}

				// Check permission of the user
				authorized := verifyUserPremission(username, groups, ocp_namespace)
				if !authorized {
					utils.ErrorHTTPResponse(w, utils.Unauthorized, "You do not have permission to read imagerepositories in " + ocp_namespace)
					return
				}
			}
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

func getToken(r *http.Request) (string) {
	token := ""
	authParts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

	if strings.ToLower(authParts[0]) == "bearer" {
		token = authParts[1]
	}
	return token
}

func verifyUserPremission(user string, groups []string, namespace string) bool {
	authorized := false
	config := &rest.Config{
		Host:        os.Getenv("CLUSTER_URL"),
		BearerToken: os.Getenv("OAUTH_TOKEN"),
	}

	// Create a Kubernetes client
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		logrus.Errorf("Error creating Kubernetes client: %s", err)
		return authorized
	}

	verbs := []string{"get", "list", "watch"}

	for _, verb := range verbs {
		// Define the permission we want to check
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:               user,
				Groups:             groups,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Group:     "appstudio.redhat.com",
					Version:   "v1alpha1",
					Namespace: namespace,
					Verb:      verb,
					Resource:  "imagerepositories",
				},
			},
		}

		// Perform the SubjectAccessReview to check the user's permissions
		sarResponse, err := client.AuthorizationV1().SubjectAccessReviews().Create(context.Background(), sar, metav1.CreateOptions{})
		if err != nil {
			logrus.Errorf("Error performing SubjectAccessReview: %s", err)
		}
		if sarResponse.Status.Allowed {
			authorized = true
			break
		}
	}

	return authorized
}
