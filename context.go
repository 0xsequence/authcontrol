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

// WithProjectID adds the project to the context.
//
// TODO: Deprecate this in favor of Session middleware with a JWT token.
func WithProjectID(ctx context.Context, project uint64) context.Context {
	return context.WithValue(ctx, ctxKeyProjectID, project)
}

// GetProjectID returns the project and if its active from the context.
// In case its not set, it will return 0.
func GetProjectID(ctx context.Context) (uint64, bool) {
	v, ok := ctx.Value(ctxKeyProjectID).(uint64)
	return v, ok
}
