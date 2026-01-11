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

	if err := viper.UnmarshalKey("organizations", &cfg.Organizations); err != nil {
		return nil, fmt.Errorf("unmarshal organizations: %w", err)
	}

	if err := viper.UnmarshalKey("connections", &cfg.Connections); err != nil {
		return nil, fmt.Errorf("unmarshal connections: %w", err)
	}

	if err := viper.UnmarshalKey("members", &cfg.Members); err != nil {
		return nil, fmt.Errorf("unmarshal members: %w", err)
	}

	if err := viper.UnmarshalKey("actions", &cfg.Actions); err != nil {
		return nil, fmt.Errorf("unmarshal actions: %w", err)
	}

	// No default users - load from config.yaml only

	for _, opt := range opts {
		opt(cfg)
	}

	// Ensure all users have identities populated
	for i := range cfg.Users {
		if len(cfg.Users[i].Identities) == 0 && cfg.Users[i].AuthMethod != "" {
			// Extract the user_id portion from the full ID (e.g., "auth0|user_devone" -> "user_devone")
			userIDPart := cfg.Users[i].ID
			if len(userIDPart) > 6 && userIDPart[:6] == "auth0|" {
				userIDPart = userIDPart[6:]
			}

			cfg.Users[i].Identities = []UserIdentity{
				{
					Connection: cfg.Users[i].AuthMethod,
					Provider:   cfg.Users[i].AuthMethod,
					UserID:     userIDPart,
					IsSocial:   false,
				},
			}
		}
	}

	return cfg, nil
}
