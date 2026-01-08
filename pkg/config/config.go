package config

type AppMetadata struct {
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
	Role     string `json:"role,omitempty" yaml:"role,omitempty"`
}

type User struct {
	ID            string                 `json:"user_id" yaml:"user_id"`
	Phone         string                 `json:"phone,omitempty" yaml:"phone,omitempty"`
	Email         string                 `json:"email" yaml:"email"`
	Name          string                 `json:"name" yaml:"name"`
	EmailVerified bool                   `json:"email_verified" yaml:"email_verified"`
	AuthMethod    string                 `json:"auth_method,omitempty" yaml:"auth_method,omitempty"` // "sms", "email", "oidc"
	AppMetadata   AppMetadata            `json:"app_metadata,omitempty" yaml:"app_metadata,omitempty"`
	UserMetadata  map[string]interface{} `json:"user_metadata,omitempty" yaml:"user_metadata,omitempty"`
	Picture       string                 `json:"picture,omitempty" yaml:"picture,omitempty"`
	Organizations []string               `json:"organizations,omitempty" yaml:"organizations,omitempty"` // Organization IDs
}

type Organization struct {
	ID          string                 `json:"id" yaml:"id"`
	Name        string                 `json:"name" yaml:"name"` // Machine name
	DisplayName string                 `json:"display_name" yaml:"display_name"`
	Branding    *OrganizationBranding  `json:"branding,omitempty" yaml:"branding,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

type OrganizationBranding struct {
	LogoURL      string            `json:"logo_url,omitempty" yaml:"logo_url,omitempty"`
	Colors       map[string]string `json:"colors,omitempty" yaml:"colors,omitempty"`
	PrimaryColor string            `json:"primary_color,omitempty" yaml:"primary_color,omitempty"`
}

type Connection struct {
	ID             string                 `json:"id" yaml:"id"`
	Name           string                 `json:"name" yaml:"name"`
	Strategy       string                 `json:"strategy" yaml:"strategy"` // "sms", "email", "oidc", "waad", "samlp"
	DisplayName    string                 `json:"display_name,omitempty" yaml:"display_name,omitempty"`
	IsDomainConn   bool                   `json:"is_domain_connection" yaml:"is_domain_connection"`
	EnabledClients []string               `json:"enabled_clients,omitempty" yaml:"enabled_clients,omitempty"`
	Options        map[string]interface{} `json:"options,omitempty" yaml:"options,omitempty"`
	Organizations  []string               `json:"organizations,omitempty" yaml:"organizations,omitempty"` // Linked org IDs
}

type OrganizationMember struct {
	UserID string `json:"user_id" yaml:"user_id"`
	OrgID  string `json:"org_id" yaml:"org_id"`
	Role   string `json:"role,omitempty" yaml:"role,omitempty"`
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
