package config

type AppMetadata struct {
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty" mapstructure:"tenant_id"`
	Role     string `json:"role,omitempty" yaml:"role,omitempty" mapstructure:"role"`
}

type UserIdentity struct {
	Connection string `json:"connection" yaml:"connection" mapstructure:"connection"`
	Provider   string `json:"provider" yaml:"provider" mapstructure:"provider"`
	UserID     string `json:"user_id" yaml:"user_id" mapstructure:"user_id"`
	IsSocial   bool   `json:"isSocial" yaml:"isSocial" mapstructure:"isSocial"`
}

type User struct {
	ID            string                 `json:"user_id" yaml:"user_id" mapstructure:"user_id"`
	Phone         string                 `json:"phone_number,omitempty" yaml:"phone" mapstructure:"phone"`
	Email         string                 `json:"email" yaml:"email" mapstructure:"email"`
	Name          string                 `json:"name" yaml:"name" mapstructure:"name"`
	EmailVerified bool                   `json:"email_verified" yaml:"email_verified" mapstructure:"email_verified"`
	Blocked       *bool                  `json:"blocked,omitempty" yaml:"blocked,omitempty" mapstructure:"blocked"`           // True if user is blocked from the application
	Identities    []UserIdentity         `json:"identities,omitempty" yaml:"identities,omitempty" mapstructure:"identities"` // Auth0 identities array
	AppMetadata   AppMetadata            `json:"app_metadata,omitempty" yaml:"app_metadata,omitempty" mapstructure:"app_metadata"`
	UserMetadata  map[string]interface{} `json:"user_metadata,omitempty" yaml:"user_metadata,omitempty" mapstructure:"user_metadata"`
	Picture       string                 `json:"picture,omitempty" yaml:"picture,omitempty" mapstructure:"picture"`
	LastLogin     *string                `json:"last_login,omitempty" yaml:"last_login,omitempty" mapstructure:"last_login"`
	Organizations []string               `json:"organizations,omitempty" yaml:"organizations,omitempty" mapstructure:"organizations"` // Organization IDs
}

type Organization struct {
	ID          string                 `json:"id" yaml:"id" mapstructure:"id"`
	Name        string                 `json:"name" yaml:"name" mapstructure:"name"` // Machine name
	DisplayName string                 `json:"display_name" yaml:"display_name" mapstructure:"display_name"`
	Branding    *OrganizationBranding  `json:"branding,omitempty" yaml:"branding,omitempty" mapstructure:"branding"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty" mapstructure:"metadata"`
}

type OrganizationBranding struct {
	LogoURL      string            `json:"logo_url,omitempty" yaml:"logo_url,omitempty" mapstructure:"logo_url"`
	Colors       map[string]string `json:"colors,omitempty" yaml:"colors,omitempty" mapstructure:"colors"`
	PrimaryColor string            `json:"primary_color,omitempty" yaml:"primary_color,omitempty" mapstructure:"primary_color"`
}

type Connection struct {
	ID             string                 `json:"id" yaml:"id" mapstructure:"id"`
	Name           string                 `json:"name" yaml:"name" mapstructure:"name"`
	Strategy       string                 `json:"strategy" yaml:"strategy" mapstructure:"strategy"` // "sms", "email", "oidc", "waad", "samlp"
	DisplayName    string                 `json:"display_name,omitempty" yaml:"display_name,omitempty" mapstructure:"display_name"`
	IsDomainConn   bool                   `json:"is_domain_connection" yaml:"is_domain_connection" mapstructure:"is_domain_connection"`
	EnabledClients []string               `json:"enabled_clients,omitempty" yaml:"enabled_clients,omitempty" mapstructure:"enabled_clients"`
	Options        map[string]interface{} `json:"options,omitempty" yaml:"options,omitempty" mapstructure:"options"`
	Organizations  []string               `json:"organizations,omitempty" yaml:"organizations,omitempty" mapstructure:"organizations"` // Linked org IDs
}

type OrganizationMember struct {
	UserID string `json:"user_id" yaml:"user_id" mapstructure:"user_id"`
	OrgID  string `json:"org_id" yaml:"org_id" mapstructure:"org_id"`
	Role   string `json:"role,omitempty" yaml:"role,omitempty" mapstructure:"role"`
}

type Branding struct {
	ServiceName  string
	LogoURL      string
	PrimaryColor string
	Title        string
	Subtitle     string
}

type Config struct {
	Issuer        string
	Audience      string
	Port          int
	CORSOrigins   []string
	Users         []User
	Organizations []Organization
	Connections   []Connection
	Members       []OrganizationMember
	Branding      Branding
	Actions       Actions
}

type Actions struct {
	PostLogin        string `json:"post_login,omitempty" yaml:"post_login,omitempty"`
	PostRegistration string `json:"post_registration,omitempty" yaml:"post_registration,omitempty"`
}
