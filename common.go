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
type Config[T any] map[string]map[string]T

// Get returns the config value for the given request.
func (c Config[T]) Get(r *rcpRequest) (v T, ok bool) {
	if c == nil || r.Package != "rpc" {
		return v, false
	}
	serviceCfg, ok := c[r.Service]
	if !ok {
		return v, false
	}
	methodCfg, ok := serviceCfg[r.Method]
	if !ok {
		return v, false
	}
	return methodCfg, true
}

// rcpRequest is a parsed RPC request.
type rcpRequest struct {
	Package string
	Service string
	Method  string
}

// newRequest parses a path into an rcpRequest.
func newRequest(path string) *rcpRequest {
	parts := strings.Split(path, "/")
	if len(parts) != 4 {
		return nil
	}
	if parts[0] != "" {
		return nil
	}
	t := rcpRequest{
		Package: parts[1],
		Service: parts[2],
		Method:  parts[3],
	}
	if t.Package == "" || t.Service == "" || t.Method == "" {
		return nil
	}
	return &t
}

// ACL is a list of session types, encoded as a bitfield.
// SessionType(n) is represented by n=-the bit.
type ACL uint64

// NewACL returns a new ACL with the given session types.
func NewACL(t ...proto.SessionType) ACL {
	var types ACL
	for _, v := range t {
		types = types.And(v)
	}
	return types
}

// And returns a new ACL with the given session types added.
func (t ACL) And(types ...proto.SessionType) ACL {
	for _, v := range types {
		t |= 1 << v
	}
	return t
}

// Includes returns true if the ACL includes the given session type.
func (t ACL) Includes(session proto.SessionType) bool {
	return t&ACL(1<<session) != 0
}
