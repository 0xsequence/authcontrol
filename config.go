package authcontrol

type ServiceConfig struct {
	URL       string `toml:"url"`        // Base URL of the service.
	JWTSecret string `toml:"jwt_secret"` // Secret used to create JWT token for S2S authentication.
	JWTToken  string `toml:"jwt_token"`  // Static JWT token used for authentication.
}
