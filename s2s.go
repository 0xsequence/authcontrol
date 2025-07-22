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
	// Service defines the "service" claim in the JWT token.
	Service string
	// JWTSecret is used to create dynamic JWT tokens for S2S auth.
	JWTSecret string
	// JWTToken is a static JWT token for S2S auth.
	JWTToken string
	// DebugRequests enables HTTP request logging.
	DebugRequests bool
}

// Service-to-service HTTP client for internal communication between Sequence services.
// If JWTSecret is provided, it will create a HS256 JWT token with the service name in the claims.
// If both JWTSecret and JWTToken are provided, JWTToken will take precedence.
func S2SClient(cfg *S2SClientConfig) *http.Client {
	serviceName := cmp.Or(cfg.Service, filepath.Base(os.Args[0]))

	httpClient := &http.Client{
		Transport: transport.Chain(http.DefaultTransport,
			traceid.Transport,
			transport.SetHeader("User-Agent", fmt.Sprintf("sequence/%s", serviceName)),
			transport.If(cfg.JWTSecret != "",
				transport.SetHeaderFunc("Authorization", func(req *http.Request) string {
					return "BEARER " + S2SToken(cfg.JWTSecret, map[string]any{"service": serviceName})
				}),
			),
			transport.If(cfg.JWTToken != "",
				transport.SetHeader("Authorization", "BEARER "+cfg.JWTToken),
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
