package authcontrol_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xsequence/authcontrol"
	"github.com/0xsequence/authcontrol/proto"
)

const HeaderKey = "Test-Key"

func keyFunc(r *http.Request) string {
	return r.Header.Get(HeaderKey)
}

type requestOption func(r *http.Request)

func accessKey(v string) requestOption {
	return func(r *http.Request) {
		r.Header.Set(HeaderKey, v)
	}
}

func jwt(v string) requestOption {
	return func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+v)
	}
}

func origin(v string) requestOption {
	return func(r *http.Request) {
		r.Header.Set("Origin", v)
	}
}

func executeRequest(t *testing.T, ctx context.Context, handler http.Handler, path string, options ...requestOption) (bool, http.Header, error) {
	req, err := http.NewRequest("POST", path, nil)
	require.NoError(t, err)

	req.Header.Set("X-Real-IP", "127.0.0.1")
	for _, opt := range options {
		opt(req)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req.WithContext(ctx))

	if status := rr.Result().StatusCode; status < http.StatusOK || status >= http.StatusBadRequest {
		webrpcErr := proto.WebRPCError{}
		err = json.Unmarshal(rr.Body.Bytes(), &webrpcErr)
		require.NoError(t, err, "failed to unmarshal response body: %s", rr.Body.Bytes())
		return false, rr.Header(), webrpcErr
	}

	return true, rr.Header(), nil
}

func TestVerify(t *testing.T) {
	services := map[string][]string{
		"Service1": {
			"Method1",
			"Method2",
			"Method3",
		},
		"Service2": {
			"Method1",
		},
	}

	// Valid ACL config
	acl := authcontrol.Config[any]{
		"Service1": {
			"Method1": authcontrol.NewACL(proto.SessionType_User),
			"Method2": authcontrol.NewACL(proto.SessionType_User),
			"Method3": authcontrol.NewACL(proto.SessionType_User),
		},
		"Service2": {
			"Method1": authcontrol.NewACL(proto.SessionType_User),
		},
	}

	err := acl.Verify(services)
	assert.NoError(t, err)

	// Wrong Service
	acl = authcontrol.Config[any]{
		"WrongService1": {
			"Method1": authcontrol.NewACL(proto.SessionType_User),
			"Method2": authcontrol.NewACL(proto.SessionType_User),
			"Method3": authcontrol.NewACL(proto.SessionType_User),
		},
		"Service2": {
			"Method1": authcontrol.NewACL(proto.SessionType_User),
		},
	}

	err = acl.Verify(services)
	require.Error(t, err)

	expectedErrors := []error{
		errors.New("Service1.Method1 not found"),
		errors.New("Service1.Method2 not found"),
		errors.New("Service1.Method3 not found"),
	}
	assert.Equal(t, errors.Join(expectedErrors...).Error(), err.Error())

	// Wrong Methods
	acl = authcontrol.Config[any]{
		"Service1": {
			"Method1": authcontrol.NewACL(proto.SessionType_User),
		},
		"Service2": {
			"Method1": authcontrol.NewACL(proto.SessionType_User),
		},
	}

	err = acl.Verify(services)
	require.Error(t, err)

	expectedErrors = []error{
		errors.New("Service1.Method2 not found"),
		errors.New("Service1.Method3 not found"),
	}
	assert.Equal(t, errors.Join(expectedErrors...).Error(), err.Error())
}
