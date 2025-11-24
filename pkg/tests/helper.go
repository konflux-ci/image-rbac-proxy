package tests

import (
	"net/http"
	"net/http/httptest"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	jwt "github.com/dgrijalva/jwt-go"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	authenticationv1.AddToScheme(scheme)
	authorizationv1.AddToScheme(scheme)
}

type Response struct {
	Code int
	Body string
}

func SimulateOpenShiftMaster(responses []Response) (*httptest.Server) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var response Response
		switch r.URL.Path {
		case "/apis/authentication.k8s.io/v1/tokenreviews":
			response = responses[0]
		case "/apis/authorization.k8s.io/v1/subjectaccessreviews":
			response = responses[1]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.Code)
		w.Write([]byte(response.Body))
	}))
	return server
}

func TrResponse(authenticated bool, username string) string {
	resp := &authenticationv1.TokenReview{}
	resp.Status = authenticationv1.TokenReviewStatus{Authenticated: authenticated, User: authenticationv1.UserInfo{Username: username}}
	return runtime.EncodeOrDie(codecs.LegacyCodec(authenticationv1.SchemeGroupVersion), resp)
}

func SarResponse(allowed bool, reason string) string {
	resp := &authorizationv1.SubjectAccessReview{}
	resp.Status = authorizationv1.SubjectAccessReviewStatus{Allowed: allowed, Reason: reason}
	return runtime.EncodeOrDie(codecs.LegacyCodec(authorizationv1.SchemeGroupVersion), resp)
}

func GenToken(t time.Time, issuer string) string {
	claims := jwt.StandardClaims{
		ExpiresAt: t.Add(time.Hour).Unix(),
		IssuedAt:  t.Unix(),
		Subject:   "foo",
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	signed, _ := token.SignedString([]byte{1, 2, 3})
	return signed
}
