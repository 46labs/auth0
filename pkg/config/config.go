package config

import "time"

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
}

type User struct {
	ID            string                 `json:"user_id" yaml:"user_id" mapstructure:"user_id"`
	Phone         string                 `json:"phone_number,omitempty" yaml:"phone" mapstructure:"phone"`
	Email         string                 `json:"email" yaml:"email" mapstructure:"email"`
	Name          string                 `json:"name" yaml:"name" mapstructure:"name"`
	EmailVerified bool                   `json:"email_verified" yaml:"email_verified" mapstructure:"email_verified"`
	Blocked       *bool                  `json:"blocked,omitempty" yaml:"blocked,omitempty" mapstructure:"blocked"`          // True if user is blocked from the application
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

// OrganizationConnection is a connection enabled on an organization: the
// /api/v2/organizations/{id}/enabled_connections sub-resource. Kept distinct
// from Connection because it describes the pairing — the per-organization
// login settings Auth0 attaches to it — not the connection definition.
//
// The connection's own name and strategy are not stored here; they are read
// from the connection registry when a response is assembled, so there is one
// source of truth for them.
type OrganizationConnection struct {
	OrgID                   string `json:"org_id"`
	ConnectionID            string `json:"connection_id"`
	AssignMembershipOnLogin bool   `json:"assign_membership_on_login"`
	IsSignupEnabled         bool   `json:"is_signup_enabled"`
	ShowAsButton            bool   `json:"show_as_button"`
}

// DeclaredOrganizationConnection is the config-file form of a pairing, kept
// separate from the resolved OrganizationConnection above because the two
// differ in exactly one way that matters: an omitted key here has to pick up
// Auth0's default rather than Go's zero value. show_as_button defaults to
// true, so a plain bool would silently disagree with what the API returns for
// the same pairing created over HTTP.
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

// OrganizationInvitation is a pending invitation to an organization. Auth0
// owns the whole acceptance lifecycle, so this record is the mock's entire
// state for it: created on POST, removed on acceptance or expiry.
type OrganizationInvitation struct {
	ID             string `json:"id" yaml:"id" mapstructure:"id"`
	OrganizationID string `json:"organization_id" yaml:"organization_id" mapstructure:"organization_id"`
	InviterName    string `json:"inviter_name" yaml:"inviter_name" mapstructure:"inviter_name"`
	InviteeEmail   string `json:"invitee_email" yaml:"invitee_email" mapstructure:"invitee_email"`
	ClientID       string `json:"client_id" yaml:"client_id" mapstructure:"client_id"`
	ConnectionID   string `json:"connection_id,omitempty" yaml:"connection_id,omitempty" mapstructure:"connection_id"`
	// TicketID is the opaque value carried in the invitation URL's
	// `invitation` query parameter and redeemed at login.
	TicketID      string      `json:"ticket_id" yaml:"ticket_id" mapstructure:"ticket_id"`
	InvitationURL string      `json:"invitation_url" yaml:"invitation_url" mapstructure:"invitation_url"`
	AppMetadata   AppMetadata `json:"app_metadata,omitempty" yaml:"app_metadata,omitempty" mapstructure:"app_metadata"`
	UserMetadata  map[string]any
	// Roles are the organization role ids granted to the invitee on
	// acceptance. The design uses this as the carrier for the admin grant.
	Roles               []string  `json:"roles,omitempty" yaml:"roles,omitempty" mapstructure:"roles"`
	SendInvitationEmail bool      `json:"send_invitation_email" yaml:"send_invitation_email" mapstructure:"send_invitation_email"`
	CreatedAt           time.Time `json:"created_at" yaml:"created_at" mapstructure:"created_at"`
	ExpiresAt           time.Time `json:"expires_at" yaml:"expires_at" mapstructure:"expires_at"`
}

// IsExpired reports whether the invitation has passed its expiry. Auth0 drops
// expired invitations from the pending list rather than surfacing them.
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

// Passwordless connection strategies. Auth0 refuses to create an organization
// invitation unless the organization has a non-passwordless connection
// enabled, because a passwordless connection has no credential for the
// invitee to set on acceptance.
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
	// InitiateLoginURI is the application's login initiation endpoint. Auth0
	// resolves an organization invitation's invitation_url against it, and
	// rejects invitation creation when the named client has none set.
	InitiateLoginURI string `json:"initiate_login_uri,omitempty" yaml:"initiate_login_uri,omitempty" mapstructure:"initiate_login_uri"`
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
	Users       []User
	// OrganizationConnections declares org/connection pairings explicitly, for
	// per-organization login settings. Pairings are also derived from each
	// Connection's Organizations list; an explicit entry here wins.
	OrganizationConnections []DeclaredOrganizationConnection
	Organizations           []Organization
	Connections             []Connection
	Members                 []OrganizationMember
	Clients                 []Client
	Branding                Branding
	Actions                 Actions
}

type Actions struct {
	PostLogin        *PostLoginAction        `json:"post_login,omitempty" yaml:"post_login,omitempty" mapstructure:"post_login"`
	PostRegistration *PostRegistrationAction `json:"post_registration,omitempty" yaml:"post_registration,omitempty" mapstructure:"post_registration"`
	TokenExchange    *TokenExchangeAction    `json:"token_exchange,omitempty" yaml:"token_exchange,omitempty" mapstructure:"token_exchange"`
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

// PostRegistrationAction declares defaults applied when a user is auto-created
// during a passwordless login (see Server.autoCreateUser). Templates resolve
// against the registration context (user, client). Not yet wired into the
// registration code path.
type PostRegistrationAction struct {
	AppMetadata  map[string]string `json:"app_metadata,omitempty" yaml:"app_metadata,omitempty" mapstructure:"app_metadata"`
	UserMetadata map[string]string `json:"user_metadata,omitempty" yaml:"user_metadata,omitempty" mapstructure:"user_metadata"`
}
