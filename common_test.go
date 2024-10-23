package authcontrol_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xsequence/authcontrol/proto"
	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/require"
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
