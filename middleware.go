package authcontrol

import (
	"errors"
	"net/http"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/0xsequence/authcontrol/proto"
)

type Options struct {
	JWTSecret  string
	KeyFuncs   []KeyFunc
	UserStore  UserStore
	ErrHandler ErrHandler
}

func Session(cfg *Options) func(next http.Handler) http.Handler {
	auth := jwtauth.New("HS256", []byte(cfg.JWTSecret), nil)

	eh := errHandler
	if cfg != nil && cfg.ErrHandler != nil {
		eh = cfg.ErrHandler
	}

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

			if cfg != nil {
				for _, f := range cfg.KeyFuncs {
					if accessKey = f(r); accessKey != "" {
						break
					}
				}
			}

			token, err := jwtauth.VerifyRequest(auth, r, jwtauth.TokenFromHeader)
			if err != nil {
				if errors.Is(err, jwtauth.ErrExpired) {
					eh(r, w, proto.ErrSessionExpired)
					return
				}

				if !errors.Is(err, jwtauth.ErrNoTokenFound) {
					eh(r, w, proto.ErrUnauthorized)
					return
				}
			}

			if token != nil {
				claims, err := token.AsMap(ctx)
				if err != nil {
					eh(r, w, err)
					return
				}

				serviceClaim, _ := claims["service"].(string)
				accountClaim, _ := claims["account"].(string)
				adminClaim, _ := claims["admin"].(bool)
				projectClaim, _ := claims["project"].(float64)

				switch {
				case serviceClaim != "":
					ctx = WithService(ctx, serviceClaim)
					sessionType = proto.SessionType_Service
				case accountClaim != "":
					ctx = WithAccount(ctx, accountClaim)
					sessionType = proto.SessionType_Wallet

					if cfg != nil && cfg.UserStore != nil {
						user, isAdmin, err := cfg.UserStore.GetUser(ctx, accountClaim)
						if err != nil {
							eh(r, w, err)
							return
						}

						if user != nil {
							ctx = withUser(ctx, user)

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
						ctx = WithProjectID(ctx, projectID)
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
func AccessControl(acl Config[ACL], cfg *Options) func(next http.Handler) http.Handler {
	eh := errHandler
	if cfg != nil && cfg.ErrHandler != nil {
		eh = cfg.ErrHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acl, err := acl.Get(r.URL.Path)
			if err != nil {
				eh(r, w, proto.ErrUnauthorized.WithCausef("get acl: %w", err))
				return
			}

			if session, _ := GetSessionType(r.Context()); !acl.Includes(session) {
				err := proto.ErrPermissionDenied
				if session == proto.SessionType_Public {
					err = proto.ErrUnauthorized
				}

				eh(r, w, err)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
