package authcontrol_test

import (
	"context"
	"testing"
	"time"

	"github.com/0xsequence/authcontrol"
	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/require"
)

func TestS2SToken(t *testing.T) {
	token := authcontrol.S2SToken(JWTSecret, map[string]any{"service": "test"})

	auth := jwtauth.New(string(authcontrol.DefaultAlgorithm), []byte(JWTSecret), nil)

	jwt, err := jwtauth.VerifyToken(auth, token)
	require.NoError(t, err)
	require.NotNil(t, jwt)

	claims, err := jwt.AsMap(context.TODO())
	require.NoError(t, err)

	expiresIn := time.Until(jwt.Expiration())
	if expiresIn < 29*time.Second {
		t.Errorf("expected default expiry to be at least 30s, got %v", expiresIn)
	}

	service := claims["service"].(string)
	if service != "test" {
		t.Errorf("unexpected service claim, got %q", service)
	}
}
