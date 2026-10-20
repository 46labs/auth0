package config

import (
	"slices"
	"time"
)

// AppMetadata mirrors Auth0's user.app_metadata — an open map, not a typed
// struct. Two keys have first-class meaning to the mock's JWT wiring
// (tenant_id, role) and are exposed via helper methods, but every other key
// (e.g. pee's org_roles) is preserved intact through PATCH/GET so SDK writes
// round-trip faithfully.
type AppMetadata map[string]any

// Well-known app_metadata keys read by the mock's JWT claim assembly.
const (
	AppMetaTenantID = "tenant_id"
	AppMetaRole     = "role"
	AppMetaOrgRoles = "org_roles"
)

// TenantID returns app_metadata.tenant_id or "" when unset or the value isn't
// a string. Nil-safe.
func (m AppMetadata) TenantID() string {
	s, _ := m[AppMetaTenantID].(string)
	return s
}

// Role returns app_metadata.role or "" when unset or the value isn't a string.
// Nil-safe.
func (m AppMetadata) Role() string {
	s, _ := m[AppMetaRole].(string)
	return s
}

// OrgRole returns app_metadata.org_roles[orgID], the per-org role model (a
// map of org id to role). Returns "" when absent or not a string. Nil-safe.
// This is a generic per-org lookup; consumers name the claim in config, not
// here.
func (m AppMetadata) OrgRole(orgID string) string {
	orgRoles, ok := m[AppMetaOrgRoles].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := orgRoles[orgID].(string)
	return s
}

type UserIdentity struct {
	Connection string `json:"connection" yaml:"connection" mapstructure:"connection"`
	Provider   string `json:"provider" yaml:"provider" mapstructure:"provider"`
	UserID     string `json:"user_id" yaml:"user_id" mapstructure:"user_id"`
	IsSocial   bool   `json:"isSocial" yaml:"isSocial" mapstructure:"isSocial"`
	// ProfileData is the linked user's profile, on a secondary identity only.
	ProfileData map[string]any `json:"profileData,omitempty" yaml:"-" mapstructure:"-"`
}

type User struct {
	ID            string                 `json:"user_id" yaml:"user_id" mapstructure:"user_id"`
	Phone         string                 `json:"phone_number,omitempty" yaml:"phone" mapstructure:"phone"`
	Email         string                 `json:"email" yaml:"email" mapstructure:"email"`
	Name          string                 `json:"name" yaml:"name" mapstructure:"name"`
	EmailVerified bool                   `json:"email_verified" yaml:"email_verified" mapstructure:"email_verified"`
	PhoneVerified *bool                  `json:"phone_verified,omitempty" yaml:"phone_verified,omitempty" mapstructure:"phone_verified"`
	Blocked       *bool                  `json:"blocked,omitempty" yaml:"blocked,omitempty" mapstructure:"blocked"`          // True if user is blocked from the application
	Identities    []UserIdentity         `json:"identities,omitempty" yaml:"identities,omitempty" mapstructure:"identities"` // Auth0 identities array
	AppMetadata   AppMetadata            `json:"app_metadata,omitempty" yaml:"app_metadata,omitempty" mapstructure:"app_metadata"`
	UserMetadata  map[string]interface{} `json:"user_metadata,omitempty" yaml:"user_metadata,omitempty" mapstructure:"user_metadata"`
	Picture       string                 `json:"picture,omitempty" yaml:"picture,omitempty" mapstructure:"picture"`
	LastLogin     *string                `json:"last_login,omitempty" yaml:"last_login,omitempty" mapstructure:"last_login"`
	LoginsCount   int                    `json:"logins_count,omitempty" yaml:"logins_count,omitempty" mapstructure:"logins_count"`
	CreatedAt     string                 `json:"created_at,omitempty" yaml:"-" mapstructure:"-"`
	UpdatedAt     string                 `json:"updated_at,omitempty" yaml:"-" mapstructure:"-"`
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

// Role is a tenant-level role. PEE resolves its admin carrier role by name at
// runtime, so ids are generated rather than configured.
type Role struct {
	ID          string `json:"id" yaml:"id" mapstructure:"id"`
	Name        string `json:"name" yaml:"name" mapstructure:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty" mapstructure:"description"`
}

type OrganizationMember struct {
	UserID string `json:"user_id" yaml:"user_id" mapstructure:"user_id"`
	OrgID  string `json:"org_id" yaml:"org_id" mapstructure:"org_id"`
	Role   string `json:"role,omitempty" yaml:"role,omitempty" mapstructure:"role"`
}

// OrganizationConnection is a connection enabled on an organization, the
// enabled_connections sub-resource. Distinct from Connection: it holds the
// per-organization login settings, not the connection definition. Name and
// strategy are projected from the connection registry at response time.
type OrganizationConnection struct {
	OrgID                   string `json:"org_id"`
	ConnectionID            string `json:"connection_id"`
	AssignMembershipOnLogin bool   `json:"assign_membership_on_login"`
	IsSignupEnabled         bool   `json:"is_signup_enabled"`
	ShowAsButton            bool   `json:"show_as_button"`
}

// DeclaredOrganizationConnection is the config-file form of a pairing.
// Separate from the resolved form because an omitted show_as_button must pick
// up Auth0's true default, not Go's false zero value.
type DeclaredOrganizationConnection struct {
	OrgID                   string `yaml:"org_id" mapstructure:"org_id"`
	ConnectionID            string `yaml:"connection_id" mapstructure:"connection_id"`
	AssignMembershipOnLogin bool   `yaml:"assign_membership_on_login" mapstructure:"assign_membership_on_login"`
	IsSignupEnabled         bool   `yaml:"is_signup_enabled" mapstructure:"is_signup_enabled"`
	ShowAsButton            *bool  `yaml:"show_as_button" mapstructure:"show_as_button"`
}

// Resolve applies Auth0's defaults, yielding the pairing as stored.
func (d DeclaredOrganizationConnection) Resolve() OrganizationConnection {
	showAsButton := true
	if d.ShowAsButton != nil {
		showAsButton = *d.ShowAsButton
	}
	return OrganizationConnection{
		OrgID:                   d.OrgID,
		ConnectionID:            d.ConnectionID,
		AssignMembershipOnLogin: d.AssignMembershipOnLogin,
		IsSignupEnabled:         d.IsSignupEnabled,
		ShowAsButton:            showAsButton,
	}
}

// Invitation TTL bounds, per the Management API's ttl_sec schema.
const (
	InvitationDefaultTTLSec = 604800  // 7 days
	InvitationMaxTTLSec     = 2592000 // 30 days
)

// OrganizationInvitation is a pending invitation: created on POST, removed on
// acceptance or expiry.
type OrganizationInvitation struct {
	ID             string `json:"id" yaml:"id" mapstructure:"id"`
	OrganizationID string `json:"organization_id" yaml:"organization_id" mapstructure:"organization_id"`
	InviterName    string `json:"inviter_name" yaml:"inviter_name" mapstructure:"inviter_name"`
	InviteeEmail   string `json:"invitee_email" yaml:"invitee_email" mapstructure:"invitee_email"`
	ClientID       string `json:"client_id" yaml:"client_id" mapstructure:"client_id"`
	ConnectionID   string `json:"connection_id,omitempty" yaml:"connection_id,omitempty" mapstructure:"connection_id"`
	// carried in the invitation URL's `invitation` parameter, redeemed at login
	TicketID      string      `json:"ticket_id" yaml:"ticket_id" mapstructure:"ticket_id"`
	InvitationURL string      `json:"invitation_url" yaml:"invitation_url" mapstructure:"invitation_url"`
	AppMetadata   AppMetadata `json:"app_metadata,omitempty" yaml:"app_metadata,omitempty" mapstructure:"app_metadata"`
	UserMetadata  map[string]any
	// role ids granted on acceptance; the carrier for the admin grant
	Roles               []string  `json:"roles,omitempty" yaml:"roles,omitempty" mapstructure:"roles"`
	SendInvitationEmail bool      `json:"send_invitation_email" yaml:"send_invitation_email" mapstructure:"send_invitation_email"`
	CreatedAt           time.Time `json:"created_at" yaml:"created_at" mapstructure:"created_at"`
	ExpiresAt           time.Time `json:"expires_at" yaml:"expires_at" mapstructure:"expires_at"`
}

// IsExpired reports whether the invitation has passed its expiry.
func (i *OrganizationInvitation) IsExpired(now time.Time) bool {
	return !i.ExpiresAt.IsZero() && now.After(i.ExpiresAt)
}

// Clone returns a deep copy of the invitation. Nil-safe.
func (i *OrganizationInvitation) Clone() *OrganizationInvitation {
	if i == nil {
		return nil
	}
	out := *i
	out.AppMetadata = i.AppMetadata.Clone()
	out.UserMetadata = cloneAnyMap(i.UserMetadata)
	if i.Roles != nil {
		out.Roles = make([]string, len(i.Roles))
		copy(out.Roles, i.Roles)
	}
	return &out
}

// Auth0 refuses to create an invitation for a passwordless connection.
const (
	StrategyEmail = "email"
	StrategySMS   = "sms"
)

// IsPasswordless reports whether the connection's strategy is one of Auth0's
// passwordless strategies.
func (c *Connection) IsPasswordless() bool {
	return c.Strategy == StrategyEmail || c.Strategy == StrategySMS
}

type Client struct {
	ClientID     string                 `json:"client_id" yaml:"client_id" mapstructure:"client_id"`
	Name         string                 `json:"name" yaml:"name" mapstructure:"name"`
	Description  string                 `json:"description,omitempty" yaml:"description,omitempty" mapstructure:"description"`
	AppType      string                 `json:"app_type,omitempty" yaml:"app_type,omitempty" mapstructure:"app_type"` // "spa", "regular_web", "non_interactive", "native"
	ClientSecret string                 `json:"client_secret,omitempty" yaml:"client_secret,omitempty" mapstructure:"client_secret"`
	Callbacks    []string               `json:"callbacks,omitempty" yaml:"callbacks,omitempty" mapstructure:"callbacks"`
	GrantTypes   []string               `json:"grant_types,omitempty" yaml:"grant_types,omitempty" mapstructure:"grant_types"`
	JWTConfig    map[string]interface{} `json:"jwt_configuration,omitempty" yaml:"jwt_configuration,omitempty" mapstructure:"jwt_configuration"`
	// login initiation endpoint; invitation_url is resolved against it
	InitiateLoginURI string `json:"initiate_login_uri,omitempty" yaml:"initiate_login_uri,omitempty" mapstructure:"initiate_login_uri"`
	// ClientMetadata is arbitrary key/value data on the application. A
	// credentials-exchange action reads it to stamp claims on M2M tokens, which
	// is how a machine credential carries an organization: Auth0 reserves the
	// native org_id claim for the organization login context, and
	// client-credentials cannot enter one.
	ClientMetadata map[string]string `json:"client_metadata,omitempty" yaml:"client_metadata,omitempty" mapstructure:"client_metadata"`
	// RefreshToken is the application's refresh token configuration. Every
	// field is stored; rotation_type and leeway drive behaviour. Without it the
	// client is non-rotating, as an Auth0 application is by default.
	RefreshToken *RefreshTokenConfig `json:"refresh_token,omitempty" yaml:"refresh_token,omitempty" mapstructure:"refresh_token"`
}

// Refresh token rotation types, as Auth0 names them.
const (
	RefreshTokenRotating    = "rotating"
	RefreshTokenNonRotating = "non-rotating"
)

// RefreshTokenConfig mirrors an Auth0 application's refresh_token settings.
type RefreshTokenConfig struct {
	// RotationType "rotating" issues a new refresh token on every refresh and
	// retires the redeemed one. "non-rotating" keeps the refresh token valid
	// and leaves it out of the refresh response.
	RotationType string `json:"rotation_type,omitempty" yaml:"rotation_type,omitempty" mapstructure:"rotation_type"`
	// Leeway is Auth0's reuse interval in seconds: for that long after a
	// rotation the retired token can still be exchanged without being taken
	// for reuse, which would revoke the whole family.
	Leeway int `json:"leeway" yaml:"leeway,omitempty" mapstructure:"leeway"`
	// The remaining fields are stored and returned, not enforced.
	ExpirationType            string               `json:"expiration_type,omitempty" yaml:"expiration_type,omitempty" mapstructure:"expiration_type"`
	TokenLifetime             *int                 `json:"token_lifetime,omitempty" yaml:"token_lifetime,omitempty" mapstructure:"token_lifetime"`
	InfiniteTokenLifetime     *bool                `json:"infinite_token_lifetime,omitempty" yaml:"infinite_token_lifetime,omitempty" mapstructure:"infinite_token_lifetime"`
	IdleTokenLifetime         *int                 `json:"idle_token_lifetime,omitempty" yaml:"idle_token_lifetime,omitempty" mapstructure:"idle_token_lifetime"`
	InfiniteIdleTokenLifetime *bool                `json:"infinite_idle_token_lifetime,omitempty" yaml:"infinite_idle_token_lifetime,omitempty" mapstructure:"infinite_idle_token_lifetime"`
	Policies                  []RefreshTokenPolicy `json:"policies,omitempty" yaml:"policies,omitempty" mapstructure:"policies"`
}

// RefreshTokenPolicy is a multi-resource refresh token policy: the API a
// refresh token may also mint access tokens for, and the scopes it grants.
type RefreshTokenPolicy struct {
	Audience string   `json:"audience" yaml:"audience" mapstructure:"audience"`
	Scope    []string `json:"scope" yaml:"scope" mapstructure:"scope"`
}

// Refresh token expiration types, as Auth0 names them.
const (
	RefreshTokenExpiring    = "expiring"
	RefreshTokenNonExpiring = "non-expiring"
)

// Lifetimes Auth0 gives a refresh token configuration that sets none.
const (
	defaultRefreshTokenLifetime     = 2592000
	defaultRefreshTokenIdleLifetime = 1296000
)

// WithDefaults fills what Auth0 fills on a client create: non-rotating,
// non-expiring, its default lifetimes, and lifetimes that are infinite only
// for a non-expiring token.
func (c *RefreshTokenConfig) WithDefaults() *RefreshTokenConfig {
	out := c.Clone()
	if out == nil {
		out = &RefreshTokenConfig{}
	}
	if out.RotationType == "" {
		out.RotationType = RefreshTokenNonRotating
	}
	if out.ExpirationType == "" {
		out.ExpirationType = RefreshTokenNonExpiring
	}
	infinite := out.ExpirationType == RefreshTokenNonExpiring
	if out.TokenLifetime == nil {
		v := defaultRefreshTokenLifetime
		out.TokenLifetime = &v
	}
	if out.IdleTokenLifetime == nil {
		v := defaultRefreshTokenIdleLifetime
		out.IdleTokenLifetime = &v
	}
	if out.InfiniteTokenLifetime == nil {
		out.InfiniteTokenLifetime = &infinite
	}
	if out.InfiniteIdleTokenLifetime == nil {
		v := infinite
		out.InfiniteIdleTokenLifetime = &v
	}
	return out
}

// Clone copies the configuration, its pointers and policies included.
func (c *RefreshTokenConfig) Clone() *RefreshTokenConfig {
	if c == nil {
		return nil
	}
	out := *c
	if c.TokenLifetime != nil {
		v := *c.TokenLifetime
		out.TokenLifetime = &v
	}
	if c.InfiniteTokenLifetime != nil {
		v := *c.InfiniteTokenLifetime
		out.InfiniteTokenLifetime = &v
	}
	if c.IdleTokenLifetime != nil {
		v := *c.IdleTokenLifetime
		out.IdleTokenLifetime = &v
	}
	if c.InfiniteIdleTokenLifetime != nil {
		v := *c.InfiniteIdleTokenLifetime
		out.InfiniteIdleTokenLifetime = &v
	}
	if c.Policies != nil {
		out.Policies = make([]RefreshTokenPolicy, len(c.Policies))
		for i, p := range c.Policies {
			out.Policies[i] = RefreshTokenPolicy{Audience: p.Audience, Scope: slices.Clone(p.Scope)}
		}
	}
	return &out
}

// RefreshTokenLeeway is the client's reuse interval.
func (c *Client) RefreshTokenLeeway() time.Duration {
	if c == nil || c.RefreshToken == nil {
		return 0
	}
	return time.Duration(c.RefreshToken.Leeway) * time.Second
}

// RotatesRefreshTokens reports whether a refresh issues a new refresh token.
func (c *Client) RotatesRefreshTokens() bool {
	return c != nil && c.RefreshToken != nil && c.RefreshToken.RotationType == RefreshTokenRotating
}

type Branding struct {
	ServiceName  string
	LogoURL      string
	PrimaryColor string
	Title        string
	Subtitle     string
}

type Config struct {
	Issuer      string
	Audience    string
	Port        int
	CORSOrigins []string
	// DeviceCodeLifetime bounds device authorization requests; zero means 15m.
	DeviceCodeLifetime time.Duration
	Users              []User
	// explicit pairings, for per-organization login settings; also derived
	// from each Connection's Organizations list, and an entry here wins
	OrganizationConnections []DeclaredOrganizationConnection
	Organizations           []Organization
	Connections             []Connection
	Roles                   []Role
	Members                 []OrganizationMember
	Clients                 []Client
	Branding                Branding
	Actions                 Actions
	// LogStreamCAFile is a PEM CA bundle trusted when delivering to log
	// streams, on top of the system pool. Empty uses the system pool alone.
	LogStreamCAFile string
}

type Actions struct {
	PostLogin           *PostLoginAction           `json:"post_login,omitempty" yaml:"post_login,omitempty" mapstructure:"post_login"`
	CredentialsExchange *CredentialsExchangeAction `json:"credentials_exchange,omitempty" yaml:"credentials_exchange,omitempty" mapstructure:"credentials_exchange"`
	PostRegistration    *PostRegistrationAction    `json:"post_registration,omitempty" yaml:"post_registration,omitempty" mapstructure:"post_registration"`
	TokenExchange       *TokenExchangeAction       `json:"token_exchange,omitempty" yaml:"token_exchange,omitempty" mapstructure:"token_exchange"`
}

// TokenExchangeAction declares how the mock services RFC 8693 token exchange
// (grant_type urn:ietf:params:oauth:grant-type:token-exchange), mirroring an
// Auth0 Custom Token Exchange profile + Action. It is intentionally generic:
// all consumer-specific claim names live in config, not in the mock's Go.
//
// The grant mints a new access token whose sub is the subject token's sub
// (the real operator, preserved for audit), org_id is the requested target
// organization, plus the claims declared below. When RequireClaim is set, the
// exchange is authorized only if the subject token carries that claim
// non-empty (the mock's stand-in for the Action's authorization check).
type TokenExchangeAction struct {
	// SubjectTokenType is the profile's subject_token_type: the request's
	// subject_token_type must match it exactly (mirrors Auth0 profile matching).
	// Auth0 rejects reserved namespaces (urn:ietf, urn:auth0, urn:okta,
	// *.auth0.com, *.okta.com), so configure a custom URN. Empty = accept any.
	SubjectTokenType string `json:"subject_token_type,omitempty" yaml:"subject_token_type,omitempty" mapstructure:"subject_token_type"`
	// RequireClaim, if set, gates the exchange: the subject token must carry
	// this (fully-qualified) claim with a non-empty value, else 403.
	RequireClaim string `json:"require_claim,omitempty" yaml:"require_claim,omitempty" mapstructure:"require_claim"`
	// CarryClaims are copied verbatim (same key) from the subject token onto
	// the minted token when present.
	CarryClaims []string `json:"carry_claims,omitempty" yaml:"carry_claims,omitempty" mapstructure:"carry_claims"`
	// SetClaims are literal key/value claims stamped on the minted token. Keys
	// are used verbatim (already namespaced in config), so org_id and
	// namespaced role/platform coexist without the mock namespacing anything.
	SetClaims map[string]string `json:"set_claims,omitempty" yaml:"set_claims,omitempty" mapstructure:"set_claims"`
	// Actor, when true, stamps the RFC 8693 `act` claim {"sub": subject.sub}
	// so the delegated token carries a native actor/audit trail.
	Actor bool `json:"actor,omitempty" yaml:"actor,omitempty" mapstructure:"actor"`
	// OrgClaim is the claim the target organization is minted under. Empty keeps
	// the native org_id, which real Auth0 issues only for a member of the target.
	OrgClaim string `json:"org_claim,omitempty" yaml:"org_claim,omitempty" mapstructure:"org_claim"`
}

// PostLoginAction declares custom claims to add to tokens issued by the
// authorization_code and refresh_token flows. Values are template strings of
// the form "${path.dot.notation}" resolved against the action context (user,
// authorization, client). A claim whose template references an empty path is
// omitted entirely, mirroring `if (event.user.x) api.idToken.setCustomClaim`.
type PostLoginAction struct {
	IDTokenClaims        map[string]string `json:"id_token_claims,omitempty" yaml:"id_token_claims,omitempty" mapstructure:"id_token_claims"`
	IDTokenRawClaims     map[string]string `json:"id_token_raw_claims,omitempty" yaml:"id_token_raw_claims,omitempty" mapstructure:"id_token_raw_claims"`
	AccessTokenClaims    map[string]string `json:"access_token_claims,omitempty" yaml:"access_token_claims,omitempty" mapstructure:"access_token_claims"`
	AccessTokenRawClaims map[string]string `json:"access_token_raw_claims,omitempty" yaml:"access_token_raw_claims,omitempty" mapstructure:"access_token_raw_claims"`
}

// CredentialsExchangeAction declares custom claims added to tokens issued by
// the client_credentials flow. Templates resolve against the exchange context
// (client), so a metadata key reaches a token as
// "${client.metadata.org_id}". A claim whose template resolves empty is
// omitted, mirroring `if (md.org_id) api.accessToken.setCustomClaim(...)`.
type CredentialsExchangeAction struct {
	AccessTokenClaims map[string]string `json:"access_token_claims,omitempty" yaml:"access_token_claims,omitempty" mapstructure:"access_token_claims"`
}

// PostRegistrationAction declares defaults applied when a user is auto-created
// during a passwordless login (see Server.autoCreateUser). Templates resolve
// against the registration context (user, client). Not yet wired into the
// registration code path.
type PostRegistrationAction struct {
	AppMetadata  map[string]string `json:"app_metadata,omitempty" yaml:"app_metadata,omitempty" mapstructure:"app_metadata"`
	UserMetadata map[string]string `json:"user_metadata,omitempty" yaml:"user_metadata,omitempty" mapstructure:"user_metadata"`
}
