package authcontrol

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const DefaultAlgorythm = string(jwa.HS256)

// AuthProvider is an interface for getting JWTAuth from a request
type AuthProvider interface {
	GetAuth(req *http.Request, options ...jwt.ValidateOption) (*jwtauth.JWTAuth, error)
}

// NewAuth creates a new AuthProvider with a static secret
func NewAuth(secret string) AuthProvider {
	return StaticAuth{Algorythm: DefaultAlgorythm, Private: []byte(secret)}
}

// StaticAuth is an AuthProvider with a static configuration
type StaticAuth struct {
	Algorythm string
	Private   []byte
	Public    []byte
}

// GetAuth returns a JWTAuth using the private secret when available, otherwise the public key
func (s StaticAuth) GetAuth(_ *http.Request, options ...jwt.ValidateOption) (*jwtauth.JWTAuth, error) {
	if s.Algorythm == "" {
		return nil, fmt.Errorf("missing algorithm")
	}

	if s.Private != nil {
		return jwtauth.New(s.Algorythm, s.Private, s.Private, options...), nil
	}

	if s.Public == nil {
		return nil, fmt.Errorf("missing public key")
	}

	block, _ := pem.Decode(s.Public)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	return jwtauth.New(s.Algorythm, nil, pub, options...), nil
}

// AuthStore is an interface for getting a StaticAuth by project ID
type AuthStore interface {
	GetAuth(ctx context.Context, projectID uint64) (*StaticAuth, error)
}

// ProjectProvider is an AuthProvider that gets the AuthProvider from a store by project ID
type ProjectProvider struct {
	Store AuthStore
}

// GetAuth checks the request JWT for a project ID claim and gets the AuthProvider from the store
func (p ProjectProvider) GetAuth(req *http.Request, options ...jwt.ValidateOption) (*jwtauth.JWTAuth, error) {
	rawToken := jwtauth.TokenFromHeader(req)
	if rawToken == "" {
		rawToken = jwtauth.TokenFromCookie(req)
	}
	if rawToken == "" {
		return nil, jwtauth.ErrNoTokenFound
	}

	token, err := jwt.ParseString(rawToken, jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claim, ok := token.PrivateClaims()["project_id"]
	if !ok {
		return nil, fmt.Errorf("empty project_id claim")
	}

	var projectID uint64

	switch val := claim.(type) {
	case float64:
		projectID = uint64(val)
	case string:
		v, _ := strconv.ParseUint(val, 10, 64)
		projectID = v
	default:
		return nil, fmt.Errorf("invalid project_id type: %T", val)
	}

	auth, err := p.Store.GetAuth(req.Context(), projectID)
	if err != nil {
		return nil, fmt.Errorf("get auth: %w", err)
	}

	if auth == nil {
		return nil, fmt.Errorf("auth not found")
	}

	return auth.GetAuth(req, options...)
}
