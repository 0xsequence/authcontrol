package authcontrol_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/assert"

	"github.com/0xsequence/authcontrol"
	"github.com/0xsequence/authcontrol/proto"
)

type mockStore map[string]bool

func (m mockStore) GetUser(ctx context.Context, address string) (any, bool, error) {
	v, ok := m[address]
	if !ok {
		return nil, false, nil
	}
	return struct{}{}, v, nil
}

type testCase struct {
	AccessKey string
	Session   proto.SessionType
	Admin     bool
}

func (t testCase) String() string {
	s := strings.Builder{}
	s.WriteString(t.Session.String())
	if t.AccessKey != "" {
		s.WriteString("/WithKey")
	}
	if t.Admin {
		s.WriteString("/Admin")
	}
	return s.String()
}

func TestSession(t *testing.T) {
	const (
		MethodPublic    = "MethodPublic"
		MethodAccount   = "MethodAccount"
		MethodAccessKey = "MethodAccessKey"
		MethodProject   = "MethodProject"
		MethodUser      = "MethodUser"
		MethodAdmin     = "MethodAdmin"
		MethodService   = "MethodService"
	)

	Methods := []string{MethodPublic, MethodAccount, MethodAccessKey, MethodProject, MethodUser, MethodAdmin, MethodService}

	ACLConfig := authcontrol.Config[authcontrol.ACL]{"Service": {
		MethodPublic:    authcontrol.NewACL(proto.SessionType_Public.OrHigher()...),
		MethodAccount:   authcontrol.NewACL(proto.SessionType_Wallet.OrHigher()...),
		MethodAccessKey: authcontrol.NewACL(proto.SessionType_AccessKey.OrHigher()...),
		MethodProject:   authcontrol.NewACL(proto.SessionType_Project.OrHigher()...),
		MethodUser:      authcontrol.NewACL(proto.SessionType_User.OrHigher()...),
		MethodAdmin:     authcontrol.NewACL(proto.SessionType_Admin.OrHigher()...),
		MethodService:   authcontrol.NewACL(proto.SessionType_Service.OrHigher()...),
	}}

	const (
		AccessKey     = "AQAAAAAAAAAHkL0mNSrn6Sm3oHs0xfa_DnY"
		WalletAddress = "walletAddress"
		UserAddress   = "userAddress"
		AdminAddress  = "adminAddress"
		ServiceName   = "serviceName"
	)

	auth := jwtauth.New("HS256", []byte("secret"), nil)

	options := &authcontrol.Options{
		UserStore: mockStore{
			UserAddress:  false,
			AdminAddress: true,
		},
		KeyFuncs: []authcontrol.KeyFunc{keyFunc},
	}

	r := chi.NewRouter()
	r.Use(
		authcontrol.Session(auth, options),
		authcontrol.AccessControl(ACLConfig, options),
	)
	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	ctx := context.Background()
	testCases := []testCase{
		{Session: proto.SessionType_Public},
		{Session: proto.SessionType_Public, AccessKey: AccessKey},
		{Session: proto.SessionType_Wallet},
		{Session: proto.SessionType_Project},
		{Session: proto.SessionType_Project, AccessKey: AccessKey},
		{Session: proto.SessionType_User},
		{Session: proto.SessionType_User, Admin: true},
		{Session: proto.SessionType_Admin},
		{Session: proto.SessionType_Admin, AccessKey: AccessKey},
		{Session: proto.SessionType_Service},
		{Session: proto.SessionType_Service, AccessKey: AccessKey},
	}

	for service := range ACLConfig {
		for _, method := range Methods {
			types := ACLConfig[service][method]
			for _, tc := range testCases {
				t.Run(path.Join(method, tc.String()), func(t *testing.T) {
					var claims map[string]any
					switch tc.Session {
					case proto.SessionType_Wallet:
						claims = map[string]any{"account": WalletAddress}
					case proto.SessionType_Project:
						claims = map[string]any{"account": WalletAddress, "project": 7}
					case proto.SessionType_User:
						address := UserAddress
						if tc.Admin {
							address = AdminAddress
						}
						claims = map[string]any{"account": address}
					case proto.SessionType_Admin:
						claims = map[string]any{"account": WalletAddress, "admin": true}
					case proto.SessionType_Service:
						claims = map[string]any{"service": ServiceName}
					}

					ok, err := executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", service, method), tc.AccessKey, mustJWT(t, auth, claims))

					session := tc.Session
					switch {
					case session == proto.SessionType_User && tc.Admin:
						session = proto.SessionType_Admin
					case session == proto.SessionType_Public && tc.AccessKey != "":
						session = proto.SessionType_AccessKey
					}

					if !types.Includes(session) {
						assert.Error(t, err)
						assert.False(t, ok)
						return
					}

					assert.NoError(t, err, "%s/%s %+v", service, method, tc)
					assert.True(t, ok)
				})
			}
		}
	}
}

func TestInvalid(t *testing.T) {
	ctx := context.Background()
	const (
		MethodName         = "MethodPublic"
		MethodNameInvalid  = MethodName + "a"
		ServiceName        = "TestService"
		ServiceNameInvalid = ServiceName + "a"
	)

	ACLConfig := authcontrol.Config[authcontrol.ACL]{
		ServiceName: {
			MethodName: authcontrol.NewACL(proto.SessionType_Public.OrHigher()...),
		},
	}

	const (
		AccessKey     = "AQAAAAAAAAAHkL0mNSrn6Sm3oHs0xfa_DnY"
		WalletAddress = "walletAddress"
		UserAddress   = "userAddress"
		AdminAddress  = "adminAddress"
	)

	auth := jwtauth.New("HS256", []byte("secret"), nil)

	options := &authcontrol.Options{
		UserStore: mockStore{
			UserAddress:  false,
			AdminAddress: true,
		},
		KeyFuncs: []authcontrol.KeyFunc{keyFunc},
	}

	r := chi.NewRouter()
	r.Use(
		authcontrol.Session(auth, options),
		authcontrol.AccessControl(ACLConfig, options),
	)
	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		resp := map[string]any{}
		resp["accessKey"], _ = authcontrol.GetAccessKey(ctx)
		resp["account"], _ = authcontrol.GetAccount(ctx)
		resp["project"], _ = authcontrol.GetProjectid(ctx)
		resp["service"], _ = authcontrol.GetService(ctx)
		resp["session"], _ = authcontrol.GetSessionType(ctx)
		resp["user"], _ = authcontrol.GetUser[any](ctx)
		assert.NoError(t, json.NewEncoder(w).Encode(resp))
	}))

	// Without JWT
	ok, err := executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodName), AccessKey, nil)
	assert.True(t, ok)
	assert.NoError(t, err)

	// Wrong JWT
	wrongJwt := "nope"
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodName), AccessKey, &wrongJwt)
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrUnauthorized)

	var claims map[string]any
	claims = map[string]any{"service": "client_service"}

	// Valid Request
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodName), AccessKey, mustJWT(t, auth, claims))
	assert.True(t, ok)
	assert.NoError(t, err)

	// Invalid request path with wrong not enough parts in path for valid RPC request
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/%s/%s", ServiceName, MethodName), AccessKey, mustJWT(t, auth, claims))
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrUnauthorized)

	// Invalid request path with wrong "rpc"
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/pcr/%s/%s", ServiceName, MethodName), AccessKey, mustJWT(t, auth, claims))
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrUnauthorized)

	// Invalid Service
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceNameInvalid, MethodName), AccessKey, mustJWT(t, auth, claims))
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrUnauthorized)

	// Invalid Method
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodNameInvalid), AccessKey, mustJWT(t, auth, claims))
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrUnauthorized)

	// Expired JWT Token
	claims["exp"] = time.Now().Add(-time.Second).Unix()
	jwt := mustJWT(t, auth, claims)

	// Expired JWT Token valid method
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodName), AccessKey, jwt)
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrSessionExpired)

	// Expired JWT Token invalid service
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceNameInvalid, MethodName), AccessKey, jwt)
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrSessionExpired)

	// Expired JWT Token invalid method
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodNameInvalid), AccessKey, jwt)
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrSessionExpired)
}

func TestCustomErrHandler(t *testing.T) {
	ctx := context.Background()
	const (
		MethodName         = "MethodPublic"
		MethodNameInvalid  = MethodName + "a"
		ServiceName        = "TestService"
		ServiceNameInvalid = ServiceName + "a"
	)

	ACLConfig := authcontrol.Config[authcontrol.ACL]{
		ServiceName: {
			MethodName: authcontrol.NewACL(proto.SessionType_Public.OrHigher()...),
		},
	}

	const (
		AccessKey    = "AQAAAAAAAAAHkL0mNSrn6Sm3oHs0xfa_DnY"
		UserAddress  = "userAddress"
		AdminAddress = "adminAddress"
	)

	customErr := proto.WebRPCError{
		Name:       "CustomErr",
		Code:       666,
		Message:    "my custom error for test cases",
		HTTPStatus: 400,
	}

	auth := jwtauth.New("HS256", []byte("secret"), nil)

	options := &authcontrol.Options{
		UserStore: mockStore{
			UserAddress:  false,
			AdminAddress: true,
		},
		KeyFuncs: []authcontrol.KeyFunc{keyFunc},
		ErrHandler: func(r *http.Request, w http.ResponseWriter, err error) {
			rpcErr := customErr

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(rpcErr.HTTPStatus)

			respBody, _ := json.Marshal(customErr)
			w.Write(respBody)
		},
	}

	r := chi.NewRouter()
	r.Use(
		authcontrol.Session(auth, options),
		authcontrol.AccessControl(ACLConfig, options),
	)
	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	var claims map[string]any
	claims = map[string]any{"service": "client_service"}

	// Valid Request
	ok, err := executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodName), AccessKey, mustJWT(t, auth, claims))
	assert.True(t, ok)
	assert.NoError(t, err)

	// Invalid service which should return custom error from overrided ErrHandler
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceNameInvalid, MethodName), AccessKey, mustJWT(t, auth, claims))
	assert.False(t, ok)
	assert.ErrorIs(t, err, customErr)
}
