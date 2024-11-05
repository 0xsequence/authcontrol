package authcontrol

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/0xsequence/authcontrol/proto"
)

// Options for the authcontrol middleware handlers Session and AccessControl.
type Options[T any, U any] struct {
	// JWT secret used to verify the JWT token.
	JWTSecret string

	// AccessKeyFuncs are used to extract the access key from the request.
	AccessKeyFuncs []AccessKeyFunc

	// UserStore is a pluggable backends that verifies if the account exists.
	UserStore UserStore[T]

	// ProjectStore is a pluggable backends that verifies if the project exists.
	ProjectStore ProjectStore[U]

	// ErrHandler is a function that is used to handle and respond to errors.
	ErrHandler ErrHandler
}

func (o *Options[T, U]) ApplyDefaults() {
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

func Session[T, U any](cfg Options[T, U]) func(next http.Handler) http.Handler {
	cfg.ApplyDefaults()
	auth := jwtauth.New("HS256", []byte(cfg.JWTSecret), nil)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// check if the request already contains session, if it does then continue
			if _, ok := GetSessionType(ctx); ok {
				next.ServeHTTP(w, r)
				return
			}

			var (
				sessionType proto.SessionType
				accessKey   string
				token       jwt.Token
			)

			for _, f := range cfg.AccessKeyFuncs {
				if accessKey = f(r); accessKey != "" {
					break
				}
			}

			token, err := jwtauth.VerifyRequest(auth, r, jwtauth.TokenFromHeader)
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
					cfg.ErrHandler(r, w, err)
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

				serviceClaim, _ := claims["service"].(string)
				accountClaim, _ := claims["account"].(string)
				adminClaim, _ := claims["admin"].(bool)
				projectClaim, _ := claims["project"].(float64)

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
						projectID := uint64(projectClaim)
						var project *U
						if cfg.ProjectStore != nil {
							if project, err = cfg.ProjectStore.GetProject(ctx, projectID); err != nil {
								cfg.ErrHandler(r, w, err)
								return
							}
							if project == nil {
								cfg.ErrHandler(r, w, proto.ErrProjectNotFound)
								return
							}
						}
						ctx = WithProjectID(ctx, projectID)
						if project != nil {
							ctx = WithProject(ctx, project)
						}
						sessionType = proto.SessionType_Project
					}
				}
			}

			if accessKey != "" && sessionType < proto.SessionType_Admin {
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
func AccessControl[T, U any](acl Config[ACL], cfg Options[T, U]) func(next http.Handler) http.Handler {
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
