package authcontrol

import (
	"maps"
	"net/http"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/traceid"
	"github.com/go-chi/transport"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type S2SClientConfig struct {
	Service       string
	JWTSecret     string
	DebugRequests bool
}

// Service-to-service HTTP client for internal communication between Sequence services.
func S2SClient(cfg *S2SClientConfig) *http.Client {
	httpClient := &http.Client{
		Transport: transport.Chain(http.DefaultTransport,
			traceid.Transport,
			transport.SetHeaderFunc("Authorization", func(req *http.Request) string {
				return "BEARER " + S2SToken(cfg.JWTSecret, map[string]any{"service": cfg.Service})
			}),
			transport.If(cfg.DebugRequests, transport.LogRequests(transport.LogOptions{Concise: true, CURL: true})),
		),
	}

	return httpClient
}

// Create short-lived service-to-service JWT token for internal communication between Sequence services.
func S2SToken(jwtSecret string, claims map[string]any) string {
	jwtAuth := jwtauth.New("HS256", []byte(jwtSecret), nil, jwt.WithAcceptableSkew(2*time.Minute))

	now := time.Now().UTC()

	c := maps.Clone(claims)
	if c == nil {
		c = map[string]any{}
	}

	c["iat"] = now

	if _, ok := c["exp"]; !ok {
		c["exp"] = now.Add(30 * time.Second)
	}

	_, t, _ := jwtAuth.Encode(c)
	return t
}
