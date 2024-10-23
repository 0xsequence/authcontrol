package authcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"

	"github.com/0xsequence/authcontrol/proto"
)

type ErrHandler func(r *http.Request, w http.ResponseWriter, err error)

func DefaultErrorHandler(r *http.Request, w http.ResponseWriter, err error) {
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

// Get returns the config value for the given request.
func (c Config[T]) Get(r *Request) (v T, ok bool) {
	if c == nil {
		return v, false
	}

	methodCfg, ok := c[r.ServiceName][r.MethodName]
	if !ok {
		return v, false
	}

	return methodCfg, true
}

// Request is a parsed RPC request.
type Request struct {
	PackageName string
	ServiceName string
	MethodName  string
}

// newRequest parses a path into an rcpRequest.
func ParseRequest(path string) *Request {
	p := strings.Split(path, "/")
	if len(p) < 4 {
		return nil
	}

	r := &Request{
		PackageName: p[len(p)-3],
		ServiceName: p[len(p)-2],
		MethodName:  p[len(p)-1],
	}

	if r.PackageName != "rpc" {
		return nil
	}

	return r
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

func VerifyACL[T any](acl Config[ACL]) error {
	var t T
	iType := reflect.TypeOf(&t).Elem()
	service := iType.Name()
	m, ok := acl[service]
	if !ok {
		return errors.New("service " + service + " not found")
	}
	var errList []error
	for i := 0; i < iType.NumMethod(); i++ {
		method := iType.Method(i)
		if _, ok := m[method.Name]; !ok {
			errList = append(errList, errors.New(""+service+"."+method.Name+" not found"))
		}
	}
	return errors.Join(errList...)
}
