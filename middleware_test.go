package authcontrol_test

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"strings"
	"testing"

	"github.com/0xsequence/authcontrol"
	"github.com/0xsequence/authcontrol/proto"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/assert"
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

	options := authcontrol.Options{
		UserStore: mockStore{
			UserAddress:  false,
			AdminAddress: true,
		},
		KeyFuncs: []authcontrol.KeyFunc{keyFunc},
	}

	r := chi.NewRouter()
	r.Use(
		authcontrol.Session(auth, &options),
		authcontrol.AccessControl(ACLConfig, &options),
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
