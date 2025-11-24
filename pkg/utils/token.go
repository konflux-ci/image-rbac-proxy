package utils

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func TokenClaims(t string) *jwt.StandardClaims {
	token, _ := jwt.ParseWithClaims(t, &jwt.StandardClaims{}, nil)
	if token == nil {
		return nil
	}
	claims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return nil
	}
	return claims
}

func IsValidToken(t string) bool {
	claims := TokenClaims(t)
	if claims != nil && claims.Valid() == nil && claims.ExpiresAt > time.Now().Add(30*time.Second).Unix() {
		return true
	}
	return false
}
