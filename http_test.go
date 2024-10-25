package authcontrol_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xsequence/authcontrol"
)

func TestS2SClient(t *testing.T) {
	secret := "secret"
	serviceName := "test-service-name"

	cfg := &authcontrol.S2SClientConfig{
		JWTSecret:       secret,
		ServiceName:     serviceName,
		TokenExpiration: 10 * time.Second,
	}

	err := cfg.Validate()
	require.NoError(t, err)

	s2sClient, err := authcontrol.S2SClient(cfg)
	require.NoError(t, err)
	require.NotNil(t, s2sClient)

	s2sClient, err = authcontrol.S2SClient(nil)
	require.Error(t, err)
	require.ErrorIs(t, err, authcontrol.ErrS2SClientConfigIsNil)
	require.Nil(t, s2sClient)

	cfg = &authcontrol.S2SClientConfig{
		JWTSecret: "",
	}
	s2sClient, err = authcontrol.S2SClient(cfg)
	require.Error(t, err)
	require.ErrorIs(t, err, authcontrol.ErrEmptyJWTSecret)
	require.Nil(t, s2sClient)

	cfg = &authcontrol.S2SClientConfig{
		JWTSecret: "",
	}
	err = cfg.Validate()
	require.Error(t, err)
	require.ErrorIs(t, err, authcontrol.ErrEmptyJWTSecret)
}

func TestS2SToken(t *testing.T) {
	ctx := context.Background()
	secret := "secret"
	serviceName := "test-service-name"

	cfg := &authcontrol.S2STokenConfig{
		JWTSecret:   secret,
		ServiceName: serviceName,
		Expiration:  10 * time.Second,
	}

	err := cfg.Validate()
	require.NoError(t, err)

	jwtAut := jwtauth.New("HS256", []byte(secret), nil)
	jwtToken := authcontrol.S2SToken(cfg)

	token, err := jwtauth.VerifyToken(jwtAut, jwtToken)
	require.NoError(t, err)

	claims, err := token.AsMap(ctx)
	require.NoError(t, err)

	cServiceName := claims["service"].(string)
	assert.Equal(t, serviceName, cServiceName)

	cfg = &authcontrol.S2STokenConfig{
		JWTSecret:  secret,
		Expiration: 10 * time.Second,
	}

	jwtToken = authcontrol.S2SToken(cfg)

	token, err = jwtauth.VerifyToken(jwtAut, jwtToken)
	require.NoError(t, err)

	claims, err = token.AsMap(ctx)
	require.NoError(t, err)

	cServiceName = claims["service"].(string)
	assert.Equal(t, os.Args[0], cServiceName)

	jwtToken = authcontrol.S2SToken(nil)
	assert.Equal(t, "", jwtToken)
}
