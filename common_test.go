package authcontrol_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/require"

	"github.com/0xsequence/authcontrol"
	"github.com/0xsequence/authcontrol/proto"
)

func mustJWT(t *testing.T, auth *jwtauth.JWTAuth, claims map[string]any) *string {
	t.Helper()
	if claims == nil {
		return nil
	}

	_, token, err := auth.Encode(claims)
	require.NoError(t, err)
	return &token
}

const HeaderKey = "Test-Key"

func keyFunc(r *http.Request) string {
	return r.Header.Get(HeaderKey)
}

func executeRequest(t *testing.T, ctx context.Context, handler http.Handler, path, accessKey string, jwt *string) (bool, error) {
	req, err := http.NewRequest("POST", path, nil)
	require.NoError(t, err)

	req.Header.Set("X-Real-IP", "127.0.0.1")
	if accessKey != "" {
		req.Header.Set(HeaderKey, accessKey)
	}

	if jwt != nil {
		req.Header.Set("Authorization", "Bearer "+*jwt)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req.WithContext(ctx))

	if status := rr.Result().StatusCode; status < http.StatusOK || status >= http.StatusBadRequest {
		w := proto.WebRPCError{}
		err = json.Unmarshal(rr.Body.Bytes(), &w)
		require.NoError(t, err)
		return false, w
	}

	return true, nil
}

func TestVerifyACL(t *testing.T) {
	type Service interface {
		Method1() error
		Method2() error
		Method3() error
	}

	err := authcontrol.VerifyACL[Service](authcontrol.Config[authcontrol.ACL]{
		"WrongName": {
			"Method1": authcontrol.NewACL(proto.SessionType_User),
			"Method2": authcontrol.NewACL(proto.SessionType_User),
			"Method3": authcontrol.NewACL(proto.SessionType_User),
		},
	})
	require.Error(t, err)

	err = authcontrol.VerifyACL[Service](authcontrol.Config[authcontrol.ACL]{
		"Service": {
			"Method1": authcontrol.NewACL(proto.SessionType_User),
			"Method2": authcontrol.NewACL(proto.SessionType_User),
		},
	})
	require.Error(t, err)

	err = authcontrol.VerifyACL[Service](authcontrol.Config[authcontrol.ACL]{
		"Service": {
			"Method1": authcontrol.NewACL(proto.SessionType_User),
			"Method2": authcontrol.NewACL(proto.SessionType_User),
			"Method3": authcontrol.NewACL(proto.SessionType_User),
		},
	})
	require.NoError(t, err)
}
