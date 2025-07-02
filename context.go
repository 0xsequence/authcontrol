package authcontrol

import (
	"context"

	"github.com/0xsequence/authcontrol/proto"
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "quotacontrol context value " + k.name
}

var (
	ctxKeySessionType = &contextKey{"SessionType"}
	ctxKeyAccount     = &contextKey{"Account"}
	ctxKeyUser        = &contextKey{"User"}
	ctxKeyService     = &contextKey{"Service"}
	ctxKeyAccessKey   = &contextKey{"AccessKey"}
	ctxKeyProjectID   = &contextKey{"ProjectID"}
	ctxKeyProject     = &contextKey{"Project"}
	ctxKeyPrefix      = &contextKey{"Prefix"}
	ctxKeyVersion     = &contextKey{"Version"}
)

//
// Session Type
//

// WithSessionType adds the access key to the context.
func WithSessionType(ctx context.Context, accessType proto.SessionType) context.Context {
	return context.WithValue(ctx, ctxKeySessionType, accessType)
}

// GetSessionType returns the access key from the context.
func GetSessionType(ctx context.Context) (proto.SessionType, bool) {
	v, ok := ctx.Value(ctxKeySessionType).(proto.SessionType)
	if !ok {
		return proto.SessionType_Public, false
	}
	return v, true
}

//
// Account
//

// WithAccount adds the account to the context.
//
// TODO: Deprecate this in favor of Session middleware with a JWT token.
func WithAccount(ctx context.Context, account string) context.Context {
	return context.WithValue(ctx, ctxKeyAccount, account)
}

// GetAccount returns the account from the context.
func GetAccount(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKeyAccount).(string)
	return v, ok
}

//
// User
//

// WithUser adds the user to the context.
//
// TODO: Deprecate this in favor of Session middleware with a JWT token.
func WithUser(ctx context.Context, user any) context.Context {
	return context.WithValue(ctx, ctxKeyUser, user)
}

// GetUser returns the user from the context.
func GetUser[T any](ctx context.Context) (*T, bool) {
	v, ok := ctx.Value(ctxKeyUser).(*T)
	return v, ok
}

//
// Service
//

// WithService adds the service to the context.
//
// TODO: Deprecate this in favor of Session middleware with a JWT token.
func WithService(ctx context.Context, service string) context.Context {
	return context.WithValue(ctx, ctxKeyService, service)
}

// GetService returns the service from the context.
func GetService(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKeyService).(string)
	return v, ok
}

//
// AccessKey
//

// WithAccessKey adds the access key to the context.
//
// TODO: Deprecate this in favor of Session middleware with a JWT token.
func WithAccessKey(ctx context.Context, accessKey string) context.Context {
	return context.WithValue(ctx, ctxKeyAccessKey, accessKey)
}

// GetAccessKey returns the access key from the context.
func GetAccessKey(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKeyAccessKey).(string)
	return v, ok
}

//
// Project ID
//

// withProjectID adds the project to the context.
func withProjectID(ctx context.Context, project uint64) context.Context {
	return context.WithValue(ctx, ctxKeyProjectID, project)
}

// GetProjectID returns the project and if its active from the context.
// In case its not set, it will return 0.
func GetProjectID(ctx context.Context) (uint64, bool) {
	v, ok := ctx.Value(ctxKeyProjectID).(uint64)
	return v, ok
}

//
// Project
//

// withProject adds the project to the context.
func withProject(ctx context.Context, project any) context.Context {
	return context.WithValue(ctx, ctxKeyProject, project)
}

// GetProject returns the project from the context.
func GetProject[T any](ctx context.Context) (*T, bool) {
	v, ok := ctx.Value(ctxKeyProject).(*T)
	return v, ok
}

// Access Key

// WithPrefix sets the prefix to the context.
func WithPrefix(ctx context.Context, prefix string) context.Context {
	return context.WithValue(ctx, ctxKeyPrefix, prefix)
}

// getPrefix returns the prefix from the context. If not set, it returns DefaultPrefix.
func getPrefix(ctx context.Context) string {
	if v, _ := ctx.Value(ctxKeyPrefix).(string); v != "" {
		return v
	}
	return DefaultPrefix
}

// WithVersion sets the version to the context.
func WithVersion(ctx context.Context, version byte) context.Context {
	return context.WithValue(ctx, ctxKeyVersion, version)
}

// GetVersion returns the version from the context. If not set, it returns AccessKeyVersion.
func GetVersion(ctx context.Context) (byte, bool) {
	v, ok := ctx.Value(ctxKeyVersion).(byte)
	return v, ok
}
