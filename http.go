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

// Service-to-service HTTP client for internal communication between Sequence services.
func S2SClient(serviceName string, jwtSecret string, debugRequests bool) *http.Client {
	httpClient := &http.Client{
		Transport: transport.Chain(http.DefaultTransport,
			traceid.Transport,
			transport.SetHeaderFunc("Authorization", s2sAuthHeader(jwtSecret, map[string]any{"service": serviceName})),
			transport.If(debugRequests, transport.LogRequests(transport.LogOptions{Concise: true, CURL: true})),
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

func s2sAuthHeader(jwtSecret string, claims map[string]any) func(req *http.Request) string {
	return func(req *http.Request) string {
		return "BEARER " + S2SToken(jwtSecret, claims)
	}
}
