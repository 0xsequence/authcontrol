package authcontrol

type ServiceConfig struct {
	// Base URL of the service.
	URL string `toml:"url"`
	// JWTSecret is used to create dynamic JWT tokens for S2S auth.
	JWTSecret string `toml:"jwt_secret"`
	// JWTToken is a static JWT token for S2S auth.
	JWTToken string `toml:"jwt_token"`
}
