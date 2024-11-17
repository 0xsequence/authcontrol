package authcontrol

import (
	"cmp"
	"net/http"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const DefaultAlgorythm = string(jwa.HS256)

type AuthProvider interface {
	GetAuth(req *http.Request, options ...jwt.ValidateOption) (*jwtauth.JWTAuth, error)
}

type StaticAuth struct {
	Algorythm string
	Secret    []byte
}

func (s StaticAuth) GetAuth(_ *http.Request, options ...jwt.ValidateOption) (*jwtauth.JWTAuth, error) {
	return jwtauth.New(cmp.Or(s.Algorythm, DefaultAlgorythm), s.Secret, nil, options...), nil
}
