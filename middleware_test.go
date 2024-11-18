package authcontrol_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xsequence/authcontrol"
	"github.com/0xsequence/authcontrol/proto"
)

// JWTSecret is the secret used to sign the JWT token in the tests.
const JWTSecret = "secret"

// MockUserStore is a simple in-memory User store for testing, it stores the address and admin status.
type MockUserStore map[string]bool

// GetUser returns the user and the admin status from the store.
func (m MockUserStore) GetUser(ctx context.Context, address string) (user any, isAdmin bool, err error) {
	v, ok := m[address]
	if !ok {
		return nil, false, nil
	}
	return struct{}{}, v, nil
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
		MethodService:   authcontrol.NewACL(proto.SessionType_InternalService.OrHigher()...),
	}}

	const (
		AccessKey     = "abcde12345"
		WalletAddress = "walletAddress"
		UserAddress   = "userAddress"
		AdminAddress  = "adminAddress"
		ServiceName   = "serviceName"
		ProjectID     = 7
	)

	options := authcontrol.Options{
		Verifier: authcontrol.NewAuth(JWTSecret),
		UserStore: MockUserStore{
			UserAddress:  false,
			AdminAddress: true,
		},
		AccessKeyFuncs: []authcontrol.AccessKeyFunc{keyFunc},
	}

	r := chi.NewRouter()
	r.Use(authcontrol.VerifyToken(options))
	r.Use(authcontrol.Session(options))
	r.Use(authcontrol.AccessControl(ACLConfig, options))

	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	ctx := context.Background()
	testCases := []struct {
		AccessKey string
		Session   proto.SessionType
		Admin     bool
	}{
		{Session: proto.SessionType_Public},
		{Session: proto.SessionType_Public, AccessKey: AccessKey},
		{Session: proto.SessionType_Wallet},
		{Session: proto.SessionType_Project},
		{Session: proto.SessionType_Project, AccessKey: AccessKey},
		{Session: proto.SessionType_User},
		{Session: proto.SessionType_User, Admin: true},
		{Session: proto.SessionType_Admin},
		{Session: proto.SessionType_Admin, AccessKey: AccessKey},
		{Session: proto.SessionType_InternalService},
		{Session: proto.SessionType_InternalService, AccessKey: AccessKey},
	}

	for service := range ACLConfig {
		for _, method := range Methods {
			types := ACLConfig[service][method]
			for _, tc := range testCases {
				s := strings.Builder{}
				fmt.Fprintf(&s, "%s/%s", method, tc.Session)
				if tc.AccessKey != "" {
					s.WriteString("+AccessKey")
				}
				if tc.Admin {
					s.WriteString("+Admin")
				}
				t.Run(s.String(), func(t *testing.T) {
					var claims map[string]any
					switch tc.Session {
					case proto.SessionType_Wallet:
						claims = map[string]any{"account": WalletAddress}
					case proto.SessionType_Project:
						claims = map[string]any{"account": WalletAddress, "project": ProjectID}
					case proto.SessionType_User:
						address := UserAddress
						if tc.Admin {
							address = AdminAddress
						}
						claims = map[string]any{"account": address}
					case proto.SessionType_Admin:
						claims = map[string]any{"account": WalletAddress, "admin": true}
					case proto.SessionType_InternalService:
						claims = map[string]any{"service": ServiceName}
					}

					var options []requestOption
					if tc.AccessKey != "" {
						options = append(options, accessKey(tc.AccessKey))
					}
					if claims != nil {
						options = append(options, jwt(authcontrol.S2SToken(JWTSecret, claims)))
					}

					ok, err := executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", service, method), options...)

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
		AccessKey     = "abcde12345"
		WalletAddress = "walletAddress"
		UserAddress   = "userAddress"
		AdminAddress  = "adminAddress"
		ProjectID     = 7
	)

	options := authcontrol.Options{
		Verifier: authcontrol.NewAuth(JWTSecret),
		UserStore: MockUserStore{
			UserAddress:  false,
			AdminAddress: true,
		},
		AccessKeyFuncs: []authcontrol.AccessKeyFunc{keyFunc},
	}

	r := chi.NewRouter()
	r.Use(authcontrol.VerifyToken(options))
	r.Use(authcontrol.Session(options))
	r.Use(authcontrol.AccessControl(ACLConfig, options))

	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		resp := map[string]any{}
		resp["accessKey"], _ = authcontrol.GetAccessKey(ctx)
		resp["account"], _ = authcontrol.GetAccount(ctx)
		resp["project"], _ = authcontrol.GetProjectID(ctx)
		resp["service"], _ = authcontrol.GetService(ctx)
		resp["session"], _ = authcontrol.GetSessionType(ctx)
		resp["user"], _ = authcontrol.GetUser[any](ctx)
		assert.NoError(t, json.NewEncoder(w).Encode(resp))
	}))

	// Without JWT
	ok, err := executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodName), accessKey(AccessKey), jwt(""))
	assert.True(t, ok)
	assert.NoError(t, err)

	// Wrong JWT
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodName), accessKey(AccessKey), jwt("wrong-secret"))
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrUnauthorized)

	claims := map[string]any{"service": "client_service"}

	// Valid Request
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodName), accessKey(AccessKey), jwt(authcontrol.S2SToken(JWTSecret, claims)))
	assert.True(t, ok)
	assert.NoError(t, err)

	// Invalid request path with wrong not enough parts in path for valid RPC request
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/%s/%s", ServiceName, MethodName), accessKey(AccessKey), jwt(authcontrol.S2SToken(JWTSecret, claims)))
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrUnauthorized)

	// Invalid request path with wrong "rpc"
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/pcr/%s/%s", ServiceName, MethodName), accessKey(AccessKey), jwt(authcontrol.S2SToken(JWTSecret, claims)))
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrUnauthorized)

	// Invalid Service
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceNameInvalid, MethodName), accessKey(AccessKey), jwt(authcontrol.S2SToken(JWTSecret, claims)))
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrUnauthorized)

	// Invalid Method
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodNameInvalid), accessKey(AccessKey), jwt(authcontrol.S2SToken(JWTSecret, claims)))
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrUnauthorized)

	// Expired JWT Token
	claims["exp"] = time.Now().Add(-5 * time.Minute).Unix() // Note: Session() middleware allows some skew.
	expiredJWT := authcontrol.S2SToken(JWTSecret, claims)

	// Expired JWT Token valid method
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodName), accessKey(AccessKey), jwt(expiredJWT))
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrSessionExpired)

	// Expired JWT Token invalid service
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceNameInvalid, MethodName), accessKey(AccessKey), jwt(expiredJWT))
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrSessionExpired)

	// Expired JWT Token invalid method
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodNameInvalid), accessKey(AccessKey), jwt(expiredJWT))
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
		AccessKey    = "abcde12345"
		UserAddress  = "userAddress"
		AdminAddress = "adminAddress"
	)

	customErr := proto.WebRPCError{
		Name:       "CustomErr",
		Code:       666,
		Message:    "my custom error for test cases",
		HTTPStatus: 400,
	}

	opts := authcontrol.Options{
		Verifier: authcontrol.NewAuth(JWTSecret),
		UserStore: MockUserStore{
			UserAddress:  false,
			AdminAddress: true,
		},
		AccessKeyFuncs: []authcontrol.AccessKeyFunc{keyFunc},
		ErrHandler: func(r *http.Request, w http.ResponseWriter, err error) {
			rpcErr := customErr

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(rpcErr.HTTPStatus)

			respBody, _ := json.Marshal(customErr)
			w.Write(respBody)
		},
	}

	r := chi.NewRouter()
	r.Use(authcontrol.VerifyToken(opts))
	r.Use(authcontrol.Session(opts))
	r.Use(authcontrol.AccessControl(ACLConfig, opts))

	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	var claims map[string]any
	claims = map[string]any{"service": "client_service"}

	// Valid Request
	ok, err := executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceName, MethodName), accessKey(AccessKey), jwt(authcontrol.S2SToken(JWTSecret, claims)))
	assert.True(t, ok)
	assert.NoError(t, err)

	// Invalid service which should return custom error from overrided ErrHandler
	ok, err = executeRequest(t, ctx, r, fmt.Sprintf("/rpc/%s/%s", ServiceNameInvalid, MethodName), accessKey(AccessKey), jwt(authcontrol.S2SToken(JWTSecret, claims)))
	assert.False(t, ok)
	assert.ErrorIs(t, err, customErr)
}

func TestOrigin(t *testing.T) {
	ctx := context.Background()

	opts := authcontrol.Options{
		Verifier: authcontrol.NewAuth(JWTSecret),
	}

	r := chi.NewRouter()
	r.Use(authcontrol.VerifyToken(opts))
	r.Use(authcontrol.Session(opts))
	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	token := authcontrol.S2SToken(JWTSecret, map[string]any{
		"user": "123",
		"ogn":  "http://localhost",
	})

	// No Origin header
	ok, err := executeRequest(t, ctx, r, "", jwt(token))
	assert.True(t, ok)
	assert.NoError(t, err)

	// Valid Origin header
	ok, err = executeRequest(t, ctx, r, "", jwt(token), origin("http://localhost"))
	assert.True(t, ok)
	assert.NoError(t, err)

	// Invalid Origin header
	ok, err = executeRequest(t, ctx, r, "", jwt(token), origin("http://evil.com"))
	assert.False(t, ok)
	assert.ErrorIs(t, err, proto.ErrUnauthorized)
}

type MockAuthStore map[uint64]authcontrol.StaticAuth

func (m MockAuthStore) GetJWTAuth(ctx context.Context, projectID uint64) (*authcontrol.StaticAuth, error) {
	auth, ok := m[projectID]
	if !ok {
		return nil, nil
	}
	return &auth, nil
}

func TestProjectVerifier(t *testing.T) {
	ctx := context.Background()

	authStore := MockAuthStore{}

	opts := authcontrol.Options{
		Verifier: authcontrol.ProjectProvider{
			Store: authStore,
		},
	}

	r := chi.NewRouter()
	r.Use(authcontrol.VerifyToken(opts))
	r.Use(authcontrol.Session(opts))
	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	projectID := uint64(7)

	authStore[projectID] = authcontrol.StaticAuth{
		Algorythm: authcontrol.DefaultAlgorithm,
		Private:   []byte(JWTSecret),
	}

	token := authcontrol.S2SToken(JWTSecret, map[string]any{
		"project_id": projectID,
	})

	ok, err := executeRequest(t, ctx, r, "", jwt(token))
	assert.True(t, ok)
	assert.NoError(t, err)

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	require.NoError(t, privateKey.Validate())

	publicRaw, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	public := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicRaw,
	})

	authStore[projectID] = authcontrol.StaticAuth{
		Algorythm: "RS256",
		Public:    public,
	}

	_, token, err = jwtauth.New("RS256", privateKey, nil).Encode(map[string]any{
		"project_id": projectID,
	})
	require.NoError(t, err)

	ok, err = executeRequest(t, ctx, r, "", jwt(token))
	assert.True(t, ok)
	assert.NoError(t, err)
}
