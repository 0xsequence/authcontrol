package authcontrol

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/0xsequence/authcontrol/proto"
)

// Options for the authcontrol middleware handlers Session and AccessControl.
type Options struct {
	// JWT secret used to verify the JWT token.
	JWTSecret string

	// ProjectStore is a pluggable backends that verifies if the project exists.
	ProjectStore ProjectStore

	// AccessKeyFuncs are used to extract the access key from the request.
	AccessKeyFuncs []AccessKeyFunc

	// UserStore is a pluggable backends that verifies if the account exists.
	UserStore UserStore

	// ErrHandler is a function that is used to handle and respond to errors.
	ErrHandler ErrHandler
}

func (o *Options) ApplyDefaults() {
	// Set default access key functions if not provided.
	// We intentionally check for nil instead of len == 0 because
	// if you can pass an empty slice to have no access key defaults.
	if o.AccessKeyFuncs == nil {
		o.AccessKeyFuncs = []AccessKeyFunc{AccessKeyFromHeader}
	}

	// Set default error handler if not provided
	if o.ErrHandler == nil {
		o.ErrHandler = errHandler
	}
}

func VerifyToken(cfg Options) func(next http.Handler) http.Handler {
	cfg.ApplyDefaults()
	jwtOptions := []jwt.ValidateOption{
		jwt.WithAcceptableSkew(2 * time.Minute),
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			auth := newAuth(cfg.JWTSecret)

			if cfg.ProjectStore != nil {
				projectID, err := findProjectClaim(r)
				if err != nil {
					cfg.ErrHandler(r, w, proto.ErrUnauthorized.WithCausef("get project claim: %w", err))
					return
				}

				project, _auth, err := cfg.ProjectStore.GetProject(ctx, projectID)
				if err != nil {
					cfg.ErrHandler(r, w, proto.ErrUnauthorized.WithCausef("get project: %w", err))
					return
				}
				if project == nil {
					cfg.ErrHandler(r, w, proto.ErrProjectNotFound)
					return
				}
				if _auth != nil {
					auth = _auth
				}
				ctx = WithProject(ctx, project)
			}

			jwtAuth, err := auth.GetVerifier(jwtOptions...)
			if err != nil {
				cfg.ErrHandler(r, w, proto.ErrUnauthorized.WithCausef("get verifier: %w", err))
				return
			}

			token, err := jwtauth.VerifyRequest(jwtAuth, r, jwtauth.TokenFromHeader)
			if err != nil {
				if errors.Is(err, jwtauth.ErrExpired) {
					cfg.ErrHandler(r, w, proto.ErrSessionExpired)
					return
				}

				if !errors.Is(err, jwtauth.ErrNoTokenFound) {
					cfg.ErrHandler(r, w, proto.ErrUnauthorized)
					return
				}
			}

			if token != nil {
				claims, err := token.AsMap(ctx)
				if err != nil {
					cfg.ErrHandler(r, w, proto.ErrUnauthorized.WithCausef("invalid token: %w", err))
					return
				}

				if originClaim, _ := claims["ogn"].(string); originClaim != "" {
					originClaim = strings.TrimSuffix(originClaim, "/")
					originHeader := strings.TrimSuffix(r.Header.Get("Origin"), "/")
					if originHeader != "" && originHeader != originClaim {
						cfg.ErrHandler(r, w, proto.ErrUnauthorized.WithCausef("invalid origin claim"))
						return
					}
				}

				ctx = jwtauth.NewContext(ctx, token, nil)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func Session(cfg Options) func(next http.Handler) http.Handler {
	cfg.ApplyDefaults()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// if a custom middleware already sets the session type, skip this middleware
			if _, ok := GetSessionType(ctx); ok {
				next.ServeHTTP(w, r)
				return
			}

			var (
				accessKey   string
				sessionType proto.SessionType
			)

			for _, f := range cfg.AccessKeyFuncs {
				if accessKey = f(r); accessKey != "" {
					break
				}
			}

			_, claims, err := jwtauth.FromContext(ctx)
			if err != nil {
				cfg.ErrHandler(r, w, err)
				return
			}
			if claims != nil {
				serviceClaim, _ := claims["service"].(string)
				accountClaim, _ := claims["account"].(string)
				adminClaim, _ := claims["admin"].(bool)
				// We support both claims for now, we'll deprecate one if we can.
				// - `project` is used by the builder to generate Project JWT tokens.
				// - `project_id` is used by API for WaaS related authentication.
				projectClaim, _ := cmp.Or(claims["project"], claims["project_id"]).(float64)

				switch {
				case serviceClaim != "":
					ctx = WithService(ctx, serviceClaim)
					sessionType = proto.SessionType_InternalService
				case accountClaim != "":
					ctx = WithAccount(ctx, accountClaim)
					sessionType = proto.SessionType_Wallet

					if cfg.UserStore != nil {
						user, isAdmin, err := cfg.UserStore.GetUser(ctx, accountClaim)
						if err != nil {
							cfg.ErrHandler(r, w, err)
							return
						}

						if user != nil {
							ctx = WithUser(ctx, user)

							sessionType = proto.SessionType_User
							if isAdmin {
								sessionType = proto.SessionType_Admin
							}
						}
					}

					if adminClaim {
						sessionType = proto.SessionType_Admin
					}

					if projectClaim > 0 {
						ctx = WithProjectID(ctx, uint64(projectClaim))
						sessionType = proto.SessionType_Project
					}
				}
			}

			if accessKey != "" {
				ctx = WithAccessKey(ctx, accessKey)
				sessionType = max(sessionType, proto.SessionType_AccessKey)
			}

			ctx = WithSessionType(ctx, sessionType)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AccessControl middleware that checks if the session type is allowed to access the endpoint.
// It also sets the compute units on the context if the endpoint requires it.
func AccessControl(acl Config[ACL], cfg Options) func(next http.Handler) http.Handler {
	cfg.ApplyDefaults()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acl, err := acl.Get(r.URL.Path)
			if err != nil {
				cfg.ErrHandler(r, w, proto.ErrUnauthorized.WithCausef("get acl: %w", err))
				return
			}

			if session, _ := GetSessionType(r.Context()); !acl.Includes(session) {
				err := proto.ErrPermissionDenied
				if session == proto.SessionType_Public {
					err = proto.ErrUnauthorized
				}

				cfg.ErrHandler(r, w, err)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// PropagateAccessKey propagates the access key from the context to other webrpc packages.
// It expectes the function `WithHTTPRequestHeaders` from the proto package that requires the access key propogation.
func PropagateAccessKey(headerContextFuncs ...func(context.Context, http.Header) (context.Context, error)) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			if accessKey, ok := GetAccessKey(ctx); ok {
				h := http.Header{
					HeaderAccessKey: []string{accessKey},
				}
				for _, fn := range headerContextFuncs {
					ctx, _ = fn(ctx, h)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
