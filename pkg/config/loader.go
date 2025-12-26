package config

import (
	"fmt"

	"github.com/spf13/viper"
)

func init() {
	viper.SetDefault("issuer", "https://auth.46labs.test/")
	viper.SetDefault("audience", "https://api.46labs.test")
	viper.SetDefault("port", 3000)
	viper.SetDefault("branding.serviceName", "Auth Service")
	viper.SetDefault("branding.primaryColor", "#3b82f6")
	viper.SetDefault("branding.title", "Sign In")
	viper.SetDefault("branding.subtitle", "Enter your phone number")

	viper.AutomaticEnv()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/config")
	viper.AddConfigPath(".")

	_ = viper.ReadInConfig()
}

type Option func(*Config)

func WithUsers(users []User) Option {
	return func(c *Config) {
		c.Users = users
	}
}

func WithBranding(b Branding) Option {
	return func(c *Config) {
		c.Branding = b
	}
}

func Load(opts ...Option) (*Config, error) {
	cfg := &Config{
		Issuer:      viper.GetString("issuer"),
		Audience:    viper.GetString("audience"),
		Port:        viper.GetInt("port"),
		CORSOrigins: viper.GetStringSlice("corsOrigins"),
		Branding: Branding{
			ServiceName:  viper.GetString("branding.serviceName"),
			LogoURL:      viper.GetString("branding.logoUrl"),
			PrimaryColor: viper.GetString("branding.primaryColor"),
			Title:        viper.GetString("branding.title"),
			Subtitle:     viper.GetString("branding.subtitle"),
		},
	}

	if len(cfg.CORSOrigins) == 0 {
		cfg.CORSOrigins = []string{"*"}
	}

	if err := viper.UnmarshalKey("users", &cfg.Users); err != nil {
		return nil, fmt.Errorf("unmarshal users: %w", err)
	}

	if len(cfg.Users) == 0 {
		cfg.Users = []User{
			{
				ID:    "user_1",
				Phone: "+14155551234",
				Email: "test@46labs.test",
				Name:  "Test User",
			},
		}
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg, nil
}
