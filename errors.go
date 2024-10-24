package authcontrol

import "fmt"

var (
	ErrEmptyJWTSecret       error = fmt.Errorf("JWTSecret is empty")
	ErrS2SClientConfigIsNil error = fmt.Errorf("S2SClientConfig is nil")
)
