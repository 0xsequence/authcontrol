package authcontrol

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v3"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/0xsequence/authcontrol/proto"
)

// Options for the authcontrol middleware handlers Session and AccessControl.
type Options struct {
	// ServiceName is the name of the service using the middleware.
	// It is used to validate the `scope` claim for admin sessions.
	ServiceName string

	// JWTsecret is required, and it is used for the JWT verification.
	// If a Project Store is also provided and the request has a project claim,
	// it could be replaced by the a specific verifier.
	JWTSecret string

	// ProjectStore is a pluggable backends that verifies if the project from the claim exists.
	// When provived, it checks the Project from the JWT, and can override the JWT Auth.
	ProjectStore ProjectStore

	// AccessKeyFuncs are used to extract the access key from the request.
	AccessKeyFuncs []AccessKeyFunc

	// UserStore is a pluggable backends that verifies if the account exists.
	// When provided, it can upgrade a Wallet session to a User or Admin session.
	UserStore UserStore

	// ErrHandler is a function that is used to handle and respond to errors.
	ErrHandler ErrHandler
}

func (o *Options) ApplyDefaults() {
	// Ensure a ServiceName is set, or else set to unknown to break scope.
	if o.ServiceName == "" {
		o.ServiceName = "!UNKNOWN!"
	}

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

			auth := NewAuth(cfg.JWTSecret)

			if cfg.ProjectStore != nil {
				projectID, err := findProjectClaim(r)
				if err != nil {
					cfg.ErrHandler(r, w, proto.ErrUnauthorized.WithCausef("find project claim: %w", err))
					return
				}

				if projectID != 0 {
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
					ctx = withProject(ctx, project)
				}

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
					cfg.ErrHandler(r, w, proto.ErrUnauthorized.WithCause(err))
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

			// If a custom middleware already sets the session type, skip this middleware.
			// This happens only in various tests and in node-gateway's specialKeyMiddleware.
			if _, ok := GetSessionType(ctx); ok {
				// Track this as a SpecialKey session for now.
				// TODO: Remove once node-gateway SpecialKey support is gone.
				w.Header().Set(HeaderSessionType, "SpecialKey")
				httplog.SetAttrs(ctx, slog.String("sessionType", "SpecialKey"))
				requestsCounter.Inc(sessionLabels{SessionType: "SpecialKey", RateLimited: "false"})
				next.ServeHTTP(w, r)
				return
			}

			_, claims, err := jwtauth.FromContext(ctx)
			if err != nil || claims == nil {
				cfg.ErrHandler(r, w, err)
				return
			}

			var (
				sessionType = proto.SessionType_Public
				projectID   uint64
			)

			// Parse JWT claims.
			serviceClaim, _ := claims["service"].(string)
			accountClaim, _ := claims["account"].(string)
			adminClaim, _ := claims["admin"].(bool)
			projectClaim, _ := claims["project"].(float64)      // Builder Admin API Secret Keys
			projectIDClaim, _ := claims["project_id"].(float64) // API->WaaS authentication
			scopeClaim, _ := claims["scope"].(string)           // use for additional context, ie. admin scope to specific service

			if serviceClaim != "" {
				sessionType = proto.SessionType_S2S

				ctx = WithService(ctx, serviceClaim)
				httplog.SetAttrs(ctx, slog.String("service", serviceClaim))
			}

			if accountClaim != "" {
				sessionType = proto.SessionType_Wallet

				ctx = WithAccount(ctx, accountClaim)
				httplog.SetAttrs(ctx, slog.String("account", accountClaim))

				if cfg.UserStore != nil {
					user, isAdmin, err := cfg.UserStore.GetUser(context.WithValue(ctx, proto.HTTPRequestCtxKey, r), accountClaim)
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
					if scopeClaim == "" || scopeClaim == cfg.ServiceName || strings.Contains(scopeClaim, cfg.ServiceName) {
						// Allow admin if no scope claim is provided or if it matches service name.
						sessionType = proto.SessionType_Admin
					} else {
						// Reduce to public if scope claim does not match.
						sessionType = proto.SessionType_Public
					}
				}
			}

			// `project` claim is used in Builder Admin API Secret Keys
			if projectClaim > 0 {
				sessionType = max(sessionType, proto.SessionType_Project)

				projectID = uint64(projectClaim)
				ctx = withProjectID(ctx, projectID)
				httplog.SetAttrs(ctx, slog.Uint64("projectId", projectID))
			}

			// `project_id` claim is used in API->WaaS authentication.
			if projectIDClaim > 0 {
				sessionType = max(sessionType, proto.SessionType_Project)

				projectID = uint64(projectIDClaim)
				ctx = withProjectID(ctx, projectID)
				httplog.SetAttrs(ctx, slog.Uint64("projectId", projectID))
			}

			// Restrict CORS for Builder Admin API Secret Keys.
			// These keys are designed for backend service use by third-party customers, not for web apps.
			if accountClaim != "" && projectClaim > 0 {
				// Secret Keys are distinguished from Wallet JWTs or Builder session JWTs
				// by the presence of both `project` and `account` claims. (As of Dec '24)
				// Related discussion: https://github.com/0xsequence/issue-tracker/issues/3802.

				origin := r.Header.Get("Origin")
				if origin != "" {
					slog.ErrorContext(ctx, "CORS disallowed for API Secret Key",
						slog.Any("error", err),
						slog.String("origin", origin),
						slog.Uint64("project_id", projectID),
					)

					err := proto.ErrSecretKeyCorsDisallowed.WithCausef("origin: %v, project_id: %v", origin, projectID)
					cfg.ErrHandler(r, w, err)
					return
				}
			}

			// Parse Access Key.
			for _, f := range cfg.AccessKeyFuncs {
				if accessKey := f(r); accessKey != "" {
					sessionType = max(sessionType, proto.SessionType_AccessKey)

					ctx = WithAccessKey(ctx, accessKey)
					if projectID == 0 {
						projectID, _ = GetProjectIDFromAccessKey(accessKey)
					}
					ctx = withProjectID(ctx, projectID)
					httplog.SetAttrs(ctx, slog.Uint64("projectId", projectID))
					break
				}
			}

			ctx = WithSessionType(ctx, sessionType)
			w.Header().Set(HeaderSessionType, sessionType.String())
			httplog.SetAttrs(ctx, slog.String("sessionType", sessionType.String()))

			ww, ok := w.(middleware.WrapResponseWriter)
			if !ok {
				ww = middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			}

			defer func() {
				// Track all requests by session type.
				requestsCounter.Inc(sessionLabels{
					SessionType: sessionType.String(),
					RateLimited: strconv.FormatBool(ww.Status() == 429),
				})

				// Track internal S2S requests by service name.
				if sessionType == proto.SessionType_S2S {
					requestsServiceCounter.Inc(serviceLabels{
						Service: serviceClaim,
					})
				}

				// Track requests by project ID.
				if projectID > 0 {
					requestsProjectCounter.Inc(projectLabels{
						ProjectID: strconv.FormatUint(projectID, 10),
						Status:    strconv.Itoa(cmp.Or(ww.Status(), 200)),
					})
				}
			}()

			next.ServeHTTP(ww, r.WithContext(ctx))
		})
	}
}

// AccessControl middleware that checks if the session type is allowed to access the endpoint.
// It also sets the compute units on the context if the endpoint requires it.
func AccessControl(acl Config[ACL], cfg Options) func(next http.Handler) http.Handler {
	cfg.ApplyDefaults()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			acl, ok := acl.Get(ctx, r.URL.Path)
			if !ok {
				// no ACL defined -> delegate to the next handler
				next.ServeHTTP(w, r)
				return
			}

			session, _ := GetSessionType(ctx)
			if acl.Includes(session) {
				next.ServeHTTP(w, r)
				return
			}

			err := proto.ErrUnauthorized
			if session > proto.SessionType_Public {
				err = proto.ErrPermissionDenied
			}
			cfg.ErrHandler(r, w, err)
		})
	}
}

// PropagateAccessKey propagates the access key from the context to other webrpc packages.
// It expects the function `WithHTTPRequestHeaders` from the proto package that requires the access key propogation.
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
