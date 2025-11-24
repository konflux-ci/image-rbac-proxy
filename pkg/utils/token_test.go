package utils

import (
	"testing"
	"time"

	"image-rbac-proxy/pkg/tests"
)

func TestIsValidToken(t *testing.T) {
	tokenTests := []struct {
		name string
		token string
		valid bool
	}{
		{
			name: "Valid token",
			token: tests.GenToken(time.Now(), "bar"),
			valid: true,
		},
		{
			name: "Expired token",
			token: tests.GenToken(time.Now().Add(-24 * time.Hour), "bar"),
			valid: false,
		},
		{
			name: "Not yet valid token",
			token: tests.GenToken(time.Now().Add(24 * time.Hour), "bar"),
			valid: false,
		},
		{
			name: "Invalid token",
			token: "123",
			valid: false,
		},
	}

	for _, tt := range tokenTests {
		t.Run(tt.name, func(t *testing.T) {
			valid := IsValidToken(tt.token)
			if valid != tt.valid {
				t.Errorf("Unexpected token validity %t", valid)
			}
		})
	}
}
