package authcontrol

type ServiceConfig struct {
	URL       string `toml:"url"`
	JWTSecret string `toml:"jwt_secret"`
	AccessKey string `toml:"access_key"`
}
