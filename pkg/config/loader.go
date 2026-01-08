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

	if len(cfg.Users) == 0 {
		cfg.Users = []User{
			{
				ID:            "auth0|user_devone",
				Phone:         "+14695550001",
				Email:         "dev.one@nextel.test",
				Name:          "Dev One",
				EmailVerified: true,
				AuthMethod:    "sms",
				AppMetadata: AppMetadata{
					TenantID: "org_nextel_test",
					Role:     "admin",
				},
				Organizations: []string{"org_nextel_test"},
			},
			{
				ID:            "auth0|user_devtwo",
				Phone:         "+17135550002",
				Email:         "dev.two@nextel.test",
				Name:          "Dev Two",
				EmailVerified: true,
				AuthMethod:    "email",
				AppMetadata: AppMetadata{
					TenantID: "org_nextel_test",
					Role:     "member",
				},
				Organizations: []string{"org_nextel_test"},
			},
			{
				ID:            "auth0|user_devthree",
				Phone:         "+12105550003",
				Email:         "dev.three@nextel.test",
				Name:          "Dev Three",
				EmailVerified: true,
				AuthMethod:    "sms",
				AppMetadata: AppMetadata{
					TenantID: "org_nextel_test",
					Role:     "member",
				},
				Organizations: []string{"org_nextel_test"},
			},
		}
	}

	if len(cfg.Organizations) == 0 {
		cfg.Organizations = []Organization{
			{
				ID:          "org_nextel_test",
				Name:        "nextel-test",
				DisplayName: "Nextel Test Organization",
				Branding: &OrganizationBranding{
					PrimaryColor: "#FFD100",
				},
				Metadata: map[string]interface{}{
					"tenant_id": "tenant_abc123",
				},
			},
		}
	}

	if len(cfg.Connections) == 0 {
		cfg.Connections = []Connection{
			{
				ID:             "con_sms",
				Name:           "sms",
				Strategy:       "sms",
				DisplayName:    "SMS",
				IsDomainConn:   false,
				EnabledClients: []string{"*"},
				Organizations:  []string{"org_nextel_test"},
			},
			{
				ID:             "con_email",
				Name:           "email",
				Strategy:       "email",
				DisplayName:    "Email",
				IsDomainConn:   false,
				EnabledClients: []string{"*"},
				Organizations:  []string{"org_nextel_test"},
			},
		}
	}

	if len(cfg.Members) == 0 {
		cfg.Members = []OrganizationMember{
			{UserID: "auth0|user_devone", OrgID: "org_nextel_test", Role: "admin"},
			{UserID: "auth0|user_devtwo", OrgID: "org_nextel_test", Role: "member"},
			{UserID: "auth0|user_devthree", OrgID: "org_nextel_test", Role: "member"},
		}
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg, nil
}
