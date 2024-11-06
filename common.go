package authcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/0xsequence/authcontrol/proto"
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

// ProjectStore is a pluggable backend that verifies if the project exists.
// If the project doesn't exist, it should return nil, nil.
type ProjectStore interface {
	GetProject(ctx context.Context, id uint64) (project any, err error)
}

// Config is a generic map of services/methods to a config value.
// map[service]map[method]T
type Config[T any] map[string]map[string]T

// Get returns the config value for the given request.
func (c Config[T]) Get(path string) (v T, err error) {
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
