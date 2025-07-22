package authcontrol

import (
	"cmp"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/traceid"
	"github.com/go-chi/transport"
)

type S2SClientConfig struct {
	// JWTToken is the JWT token to use for authentication.
	JWTToken string
	// JWTSecret is the secret key used to create the JWT token.
	JWTSecret string
	// Service is used in the service claim of the JWT token.
	Service string
	// AccessKey is an optional access key to use for authentication.
	AccessKey string
	// DebugRequests enables logging of HTTP requests.
	DebugRequests bool
}

// Service-to-service HTTP client for internal communication between Sequence services.
func S2SClient(cfg *S2SClientConfig) *http.Client {
	serviceName := cmp.Or(cfg.Service, filepath.Base(os.Args[0]))

	httpClient := &http.Client{
		Transport: transport.Chain(http.DefaultTransport,
			traceid.Transport,
			transport.SetHeader("User-Agent", fmt.Sprintf("sequence/%s", serviceName)),
			transport.If(cfg.JWTSecret != "" || cfg.JWTToken != "",
				transport.SetHeaderFunc("Authorization", func(req *http.Request) string {
					token := cfg.JWTToken
					if token == "" {
						token = S2SToken(cfg.JWTSecret, map[string]any{"service": serviceName})
					}
					return "BEARER " + token
				}),
			),
			transport.If(cfg.AccessKey != "",
				transport.SetHeader("X-Access-Key", cfg.AccessKey),
			),
			transport.If(cfg.DebugRequests,
				transport.LogRequests(transport.LogOptions{Concise: true, CURL: true}),
			),
		),
	}
	return httpClient
}

// Create a short-lived service-to-service JWT token for internal communication between Sequence services.
func S2SToken(jwtSecret string, claims map[string]any) string {
	jwtAuth, _ := NewAuth(jwtSecret).GetVerifier(nil)
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
