package config

import (
	"errors"
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
	// A missing file is fine; a malformed one is not. Swallowing this left the
	// server running with no file-backed users, organizations or clients and
	// no indication why. Returned rather than fatal, so importing this package
	// cannot kill the process.
	if err := viper.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("reading config %s: %w", viper.ConfigFileUsed(), err)
		}
	}

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

	if err := viper.UnmarshalKey("roles", &cfg.Roles); err != nil {
		return nil, fmt.Errorf("unmarshal roles: %w", err)
	}

	if err := viper.UnmarshalKey("members", &cfg.Members); err != nil {
		return nil, fmt.Errorf("unmarshal members: %w", err)
	}

	if err := viper.UnmarshalKey("organizationConnections", &cfg.OrganizationConnections); err != nil {
		return nil, fmt.Errorf("unmarshal organizationConnections: %w", err)
	}

	if err := viper.UnmarshalKey("clients", &cfg.Clients); err != nil {
		return nil, fmt.Errorf("unmarshal clients: %w", err)
	}

	if err := viper.UnmarshalKey("actions", &cfg.Actions); err != nil {
		return nil, fmt.Errorf("unmarshal actions: %w", err)
	}

	// No default users - load from config.yaml only

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg, nil
}
