package authcontrol

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/0xsequence/authcontrol/proto"
)

func defaultErrHandler(r *http.Request, w http.ResponseWriter, err error) {
	rpcErr, ok := err.(proto.WebRPCError)
	if !ok {
		rpcErr = proto.ErrWebrpcEndpoint.WithCause(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rpcErr.HTTPStatus)

	respBody, _ := json.Marshal(rpcErr)
	w.Write(respBody)
}

type KeyFunc func(*http.Request) string

type UserStore interface {
	GetUser(ctx context.Context, address string) (any, bool, error)
}

// Config is a generic map of services/methods to a config value.
// map[service]map[method]T
type Config[T any] map[string]map[string]T

// returns the config value for the given request.
func (c Config[T]) Get(r *rcpRequest) (v T, ok bool) {
	if c == nil {
		return v, false
	}

	methodCfg, ok := c[r.serviceName][r.methodName]
	if !ok {
		return v, false
	}

	return methodCfg, true
}

// rcpRequest is a parsed RPC request.
type rcpRequest struct {
	packageName string
	serviceName string
	methodName  string
}

// newRequest parses a path into an rcpRequest.
func newRequest(path string) *rcpRequest {
	p := strings.Split(path, "/")
	if len(p) < 4 {
		return nil
	}

	t := &rcpRequest{
		packageName: p[len(p)-3],
		serviceName: p[len(p)-2],
		methodName:  p[len(p)-1],
	}

	if t.packageName != "rpc" {
		return nil
	}

	return t
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
