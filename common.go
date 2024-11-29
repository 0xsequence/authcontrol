package authcontrol

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/0xsequence/authcontrol/proto"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	HeaderAccessKey = "X-Access-Key"
)

type AccessKeyFunc func(*http.Request) string

func AccessKeyFromHeader(r *http.Request) string {
	return r.Header.Get(HeaderAccessKey)
}

type ErrHandler func(r *http.Request, w http.ResponseWriter, err error)

func errHandler(r *http.Request, w http.ResponseWriter, err error) {
	rpcErr, ok := err.(proto.WebRPCError)
	if !ok {
		rpcErr = proto.ErrWebrpcEndpoint.WithCause(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rpcErr.HTTPStatus)

	respBody, _ := json.Marshal(rpcErr)
	w.Write(respBody)
}

// UserStore is a pluggable backend that verifies if a user exists.
// If the account doesn't exist, it should return nil, false, nil.
type UserStore interface {
	GetUser(ctx context.Context, address string) (user any, isAdmin bool, err error)
}

// ProjectStore is a pluggable backend that verifies if a project exists.
// If the project does not exist, it should return nil, nil, nil.
// The optional Auth, when returned, will be used for instead of the standard one.
type ProjectStore interface {
	GetProject(ctx context.Context, id uint64) (project any, auth *Auth, err error)
}

// Config is a generic map of services/methods to a config value.
// map[service]map[method]T
type Config[T any] map[string]map[string]T

// Get returns the config value for the given request.
func (c Config[T]) Get(_ context.Context, path string) (v T, err error) {
	if c == nil {
		return v, fmt.Errorf("config is nil")
	}

	p := strings.Split(path, "/")
	if len(p) < 4 {
		return v, fmt.Errorf("path has not enough parts")
	}

	var (
		packageName = p[len(p)-3]
		serviceName = p[len(p)-2]
		methodName  = p[len(p)-1]
	)

	if packageName != "rpc" {
		return v, fmt.Errorf("path doesn't include rpc")
	}

	v, ok := c[serviceName][methodName]
	if !ok {
		return v, fmt.Errorf("acl not found")
	}

	return v, nil
}

// Verify checks that the given config is valid for the given service.
// It can be used in unit tests to ensure that all methods are covered.
func (c Config[any]) Verify(webrpcServices map[string][]string) error {
	var errList []error
	for service, methods := range webrpcServices {
		for _, method := range methods {
			if _, ok := c[service][method]; !ok {
				errList = append(errList, fmt.Errorf("%s.%s not found", service, method))
			}
		}
	}

	return errors.Join(errList...)
}

// ACL is a list of session types, encoded as a bitfield.
// SessionType(n) is represented by n=-the bit.
type ACL uint64

// NewACL returns a new ACL with the given session types.
func NewACL(sessions ...proto.SessionType) ACL {
	var acl ACL
	for _, v := range sessions {
		acl = acl.And(v)
	}
	return acl
}

// And returns a new ACL with the given session types added.
func (a ACL) And(session ...proto.SessionType) ACL {
	for _, v := range session {
		a |= 1 << v
	}
	return a
}

// Includes returns true if the ACL includes the given session type.
func (t ACL) Includes(session proto.SessionType) bool {
	return t&ACL(1<<session) != 0
}

// NewAuth creates a new Auth HS256 with the given secret.
func NewAuth(secret string) *Auth {
	return &Auth{Algorithm: jwa.HS256, Private: []byte(secret)}
}

// Auth is a struct that holds the private and public keys for JWT signing and verification.
type Auth struct {
	Algorithm jwa.SignatureAlgorithm
	Private   []byte
	Public    []byte
}

// GetVerifier returns a JWTAuth using the private secret when available, otherwise the public key
func (a Auth) GetVerifier(options ...jwt.ValidateOption) (*jwtauth.JWTAuth, error) {
	if a.Algorithm == "" {
		return nil, fmt.Errorf("missing algorithm")
	}

	if a.Private != nil {
		return jwtauth.New(string(a.Algorithm), a.Private, a.Private, options...), nil
	}

	if a.Public == nil {
		return nil, fmt.Errorf("missing public key")
	}

	block, _ := pem.Decode(a.Public)

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	return jwtauth.New(a.Algorithm.String(), nil, pub, options...), nil
}

// findProjectClaim looks for the project_id/project claim in the JWT
func findProjectClaim(r *http.Request) (uint64, error) {
	raw := jwtauth.TokenFromHeader(r)
	if raw == "" {
		return 0, nil
	}

	token, err := jwt.ParseString(raw, jwt.WithVerify(false))
	if err != nil {
		return 0, fmt.Errorf("parse token: %w", err)
	}

	claims := token.PrivateClaims()

	claim := cmp.Or(claims["project_id"], claims["project"])
	if claim == nil {
		return 0, nil
	}

	switch val := claim.(type) {
	case float64:
		return uint64(val), nil
	case string:
		v, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid value")
		}
		return v, nil
	default:
		return 0, fmt.Errorf("invalid type: %T", val)
	}
}
