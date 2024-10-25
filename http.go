package authcontrol

import (
	"cmp"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/traceid"
	"github.com/go-chi/transport"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	defaultExpiration time.Duration = 30 * time.Second
	acceptableSkew    time.Duration = 2 * time.Minute
)

type S2SClientConfig struct {
	ServiceName     string
	JWTSecret       string
	DebugRequests   bool
	TokenExpiration time.Duration
}

func (cfg *S2SClientConfig) Validate() error {
	if cfg.JWTSecret == "" {
		return ErrEmptyJWTSecret
	}

	return nil
}

// Service-to-service HTTP client for internal communication between Sequence services.
func S2SClient(cfg *S2SClientConfig) (*http.Client, error) {
	if cfg == nil {
		return nil, ErrS2SClientConfigIsNil
	}

	if cfg.JWTSecret == "" {
		return nil, ErrEmptyJWTSecret
	}

	tokenCfg := &S2STokenConfig{
		JWTSecret:   cfg.JWTSecret,
		ServiceName: cfg.ServiceName,
		Expiration:  cfg.TokenExpiration,
	}

	httpClient := &http.Client{
		Transport: transport.Chain(http.DefaultTransport,
			traceid.Transport,
			transport.SetHeaderFunc("Authorization", s2sAuthHeader(tokenCfg)),
			transport.If(cfg.DebugRequests, transport.LogRequests(transport.LogOptions{Concise: true, CURL: true})),
		),
	}

	return httpClient, nil
}

func s2sAuthHeader(cfg *S2STokenConfig) func(req *http.Request) string {
	return func(req *http.Request) string {
		return "BEARER " + S2SToken(cfg)
	}
}

type S2STokenConfig struct {
	JWTSecret   string
	ServiceName string
	Expiration  time.Duration
}

func (cfg *S2STokenConfig) Validate() error {
	if cfg.JWTSecret == "" {
		return ErrEmptyJWTSecret
	}

	return nil
}

// Create short-lived service-to-service JWT token for internal communication between Sequence services with HS256 algorithm.
func S2SToken(cfg *S2STokenConfig) string {
	if cfg == nil {
		return ""
	}

	jwtAuth := jwtauth.New("HS256", []byte(cfg.JWTSecret), nil, jwt.WithAcceptableSkew(acceptableSkew))

	now := time.Now().UTC()
	claims := map[string]any{
		"service": cmp.Or(cfg.ServiceName, os.Args[0]),
		"iat":     now,
		"exp":     now.Add(cmp.Or(cfg.Expiration, defaultExpiration)),
	}

	_, t, _ := jwtAuth.Encode(claims)

	return t
}
