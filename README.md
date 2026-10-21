# auth0

Full-featured OIDC provider mock with Auth0-compatible API for local development and testing.

## Features

### OIDC & OAuth2
- Complete OIDC/OAuth2 implementation (discovery, JWKS, authorize, token, userinfo)
- PKCE support
- SMS and email passwordless authentication
- RFC 8628 device authorization for native/public clients
- Actions: declarative claims and scripted post-login code deployed through the Management API
- Login hint support for pre-filling user identifiers
- Configurable custom claims with namespace support
- Multi-tenancy with organizations

### Auth0 Management API Mock
- Organizations CRUD (`/api/v2/organizations`)
- Organization invitations: create, list, read, revoke
- Organization enabled connections (`/api/v2/organizations/:id/enabled_connections`)
- Roles registry (`/api/v2/roles`), including `name_filter` for read-or-create by name
- Connections management (`/api/v2/connections`)
- Clients CRUD (`/api/v2/clients`), including `initiate_login_uri` and `client_metadata`
- User metadata updates (`/api/v2/users/:id`)
- Passwordless user creation (`POST /api/v2/users`), lookup by email (`/api/v2/users-by-email`) and
  identity linking (`POST /api/v2/users/:id/identities`)
- Organization membership and member roles
- Token exchange profiles (`/api/v2/token-exchange-profiles`), checkpoint-paginated; `include_totals` is refused as Auth0 refuses it
- Log streams (`/api/v2/log-streams`), with delivery of sign-in and token exchange events to `http` streams
- Self-Service SSO profiles and tickets (`/api/v2/self-service-profiles`), with a setup page
- Page-based pagination (`page`, `per_page`) on every list endpoint

### Organization login
- Org-scoped login via the `organization` authorize parameter, gated on membership
- `assign_membership_on_login` so a directory self-serves into an organization
- Invitation acceptance via the `invitation` parameter: creates the user, joins the
  organization, applies the invitation's role and metadata, and consumes the ticket
- `app_metadata.org_roles[org_id]` seeded from the member role on login, mirroring the
  production Post-Login Action

### Developer Experience
- Dynamic login UI supporting both email and SMS
- Customizable branding and templates
- Configurable via YAML or environment variables
- Declarative Actions for shaping token claims (`post_login` trigger)
- Hot-reload development with Tilt
- Multi-arch support (amd64 + arm64)

## Quick Start

```bash
# Simple docker run
just docker

# Full Kind cluster with Tilt + Ingress + TLS
just kind

# Run tests
just ci
```

## Development Modes

### Docker (Simple)
```bash
just docker  # Runs on http://localhost:4646
just down    # Stop container
```

### Kind + Tilt (Full Stack)
```bash
just kind    # Creates cluster, ingress, TLS, starts Tilt
# Access: https://auth.46labs.test
just down    # Destroy cluster
```

Tilt provides:
- Hot-reload on code changes
- Web UI at http://localhost:10350
- Full ingress + TLS setup

## Configuration

### Environment Variables

```bash
ISSUER=https://auth.example.com/
AUDIENCE=https://api.example.com
PORT=3000
CORSORIGINS=https://app.example.com,https://admin.example.com
DEVICECODELIFETIME=15m
```

### YAML Configuration

See `config.yaml` for full example with users, organizations, connections, and members.

```yaml
issuer: "https://auth.example.test/"
audience: "https://api.example.test"
port: 3001

branding:
  serviceName: "MyApp"
  primaryColor: "#3b82f6"
  title: "Welcome"
  subtitle: "Sign in to continue"

users:
  - user_id: "auth0|user_1"
    email: "user@example.com"
    phone: "+14155551234"
    name: "Test User"
    email_verified: true
    auth_method: "sms"  # or "email"
    app_metadata:
      tenant_id: "org_1"
      role: "admin"
    organizations:
      - "org_1"

organizations:
  - id: "org_1"
    name: "my-org"
    display_name: "My Organization"
    branding:
      primary_color: "#3b82f6"
    metadata:
      tenant_id: "tenant_123"

connections:
  - id: "con_sms"
    name: "sms"
    strategy: "sms"
    display_name: "SMS"
    organizations:
      - "org_1"

members:
  - user_id: "auth0|user_1"
    org_id: "org_1"
    role: "admin"
```

### Custom Login Template

Mount your HTML at `/config/login.html` or use the Helm chart:

```yaml
customLogin:
  enabled: true
  html: |
    <!DOCTYPE html>
    <html>
    <!-- Your custom template -->
    </html>
```

Template must include `{{.SessionID}}` in form and support both `phone`, `email`, or `identifier` fields.

### Custom Device Template

The `/device` verification page is customized the same way. The mock loads the first of
`/config/device.html`, `templates/device.html` (shipped in the image), or a minimal built-in page.
Each page resolves on its own, so a custom login page does not change the device page.

```yaml
customDevice:
    enabled: true
    html: |
        <!DOCTYPE html>
        <html>
        <!-- Your custom template -->
        </html>
```

The template renders three states from this data:

| Field | When | Value |
|---|---|---|
| `.Branding` | always | `ServiceName`, `LogoURL`, `PrimaryColor`, `Title`, `Subtitle` |
| `.UserCode` | confirm | user code, formatted `XXXX-XXXX` |
| `.ClientName` | confirm | client `name`, else `client_id` |
| `.Audience` | confirm | requested audience |
| `.Scope` | confirm | space-separated scopes |
| `.Message` | result | approved or denied text |

With neither `.UserCode` nor `.Message`, render the entry form: `GET /device` with `user_code`.
The confirm form posts to `/device` with `user_code` (hidden), `confirm_user_code`, `identifier`,
`code`, and a submit named `decision` with value `approve` or `deny`. Errors are returned as plain
text, as on the login page.

## Authentication Flows

### SMS Passwordless

```bash
# User enters phone number
POST /authorize
  phone: "+14155551234"
  session_id: "..."

# User enters verification code (dev code: 123456)
POST /authorize
  phone: "+14155551234"
  code: "123456"
  session_id: "..."

# Exchange authorization code for tokens
POST /oauth/token
  grant_type: authorization_code
  code: "..."
  client_id: "..."
  redirect_uri: "..."
  code_verifier: "..."  # PKCE
```

### Email Passwordless

Same flow as SMS, but use `email` or `identifier` field instead of `phone`.

```bash
POST /authorize
  identifier: "user@example.com"
  code: "123456"
  session_id: "..."
```

### Login Hint

Pre-fill the login form with a user's email or phone number using the `login_hint` parameter:

```bash
GET /authorize?login_hint=user@domain.com&...
GET /authorize?login_hint=%2B14695551212&...
```

### Device Authorization

Native clients declare the `urn:ietf:params:oauth:grant-type:device_code` grant
in `grant_types`. They do not need a client secret for this flow.

```bash
curl -sS -X POST http://localhost:4646/oauth/device/code \
  -d client_id=dev_device_client \
  -d audience=https://localhost:3000 \
  -d 'scope=openid profile email offline_access'
```

The response contains a `device_code`, an eight-character `user_code`, and a
`verification_uri_complete`. Open the complete URI in a browser, or open
`verification_uri` and enter the user code, then approve the request with a
configured local user. The mock uses verification code
`123456` and keeps device transactions in memory for 15 minutes; set
`deviceCodeLifetime` (a duration such as `5s`) to shorten that when testing
`expired_token`. Clients
should poll `/oauth/token` no faster than the returned five-second `interval`.
For a user-info-only token, omit `audience`; custom API requests must name the
configured audience.

```bash
curl -sS -X POST http://localhost:4646/oauth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
  -d client_id=dev_device_client \
  -d device_code=...
```

Pending and denied/expired authorization responses use HTTP 403; overly fast
polling uses HTTP 429 with `slow_down`, which increases the required interval
by five seconds. A successful response includes an ID token only when
`openid` was requested and a refresh token only when `offline_access` was
requested. The configured `audience` is authoritative, and API scopes must be
authorized by the matching client grant.

Refreshing follows the client's refresh token rotation, as in Auth0. By default a
client is non-rotating: the refresh response has no `refresh_token`, and the
redeemed refresh token stays valid. A rotating client gets a new refresh token on
every refresh. Reusing a retired one is a breach: it gets HTTP 403 `invalid_grant`,
and every token rotated from the same login is revoked. Within `leeway` seconds
(Auth0's reuse interval) the most recently retired token is still exchanged, so
concurrent refreshes do not trip it:

```yaml
clients:
  - client_id: dev_device_client
    app_type: native
    grant_types: [urn:ietf:params:oauth:grant-type:device_code, refresh_token]
    refresh_token:
      rotation_type: rotating   # or non-rotating (the default)
      leeway: 120               # reuse interval in seconds (default 0)
```

## Custom Claims

Tokens automatically include custom claims from `app_metadata` using the issuer as namespace:

```json
{
  "sub": "auth0|user_1",
  "email": "user@example.com",
  "https://auth.example.com/tenant_id": "org_1",
  "https://auth.example.com/role": "admin"
}
```

The namespace is derived from the `issuer` configuration, ensuring uniqueness and avoiding claim collisions.

## Actions

Declarative replacement for Auth0 Actions / Rules. Configured under `actions:` in `config.yaml`. The `post_login` trigger fires on the `authorization_code`, device-code, and `refresh_token` flows and lets you shape custom claims without writing JavaScript.

```yaml
actions:
  post_login:
    # Namespaced claims (prefixed with the issuer URL)
    id_token_claims:
      role: "${user.app_metadata.role}"
      phone_number: "${user.phone_number}"
    # Top-level claims (no namespace) — for Auth0 standard claims like org_id
    id_token_raw_claims:
      org_id: "${user.app_metadata.tenant_id}"
    access_token_claims:
      role: "${authorization.role}"
      phone_number: "${user.phone_number}"
    access_token_raw_claims:
      org_id: "${user.app_metadata.tenant_id}"
```

Template syntax: `${path.dot.notation}`. Literals (no `${...}`) pass through unchanged. A claim whose template references an empty or missing path is **omitted** — matching the `if (event.user.x) api.idToken.setCustomClaim(...)` pattern in real Auth0 Actions.

Available context paths:

| Path | Source |
|------|--------|
| `user.user_id`, `user.email`, `user.phone_number`, `user.name` | User profile fields |
| `user.app_metadata.tenant_id`, `user.app_metadata.role` | User `app_metadata` |
| `user.user_metadata.*` | User `user_metadata` (any nested key) |
| `authorization.role`, `authorization.org_id` | Looked up from `members` by the user's `app_metadata.tenant_id` |
| `client.client_id`, `client.name` | The requesting client |

Equivalent to the following Auth0 Action snippet:

```js
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://auth.example.test';
  if (event.authorization?.role) {
    api.idToken.setCustomClaim(`${namespace}/role`, event.user.app_metadata.role);
    api.accessToken.setCustomClaim(`${namespace}/role`, event.authorization.role);
  }
  if (event.user.phone_number) {
    api.idToken.setCustomClaim(`${namespace}/phone_number`, event.user.phone_number);
    api.accessToken.setCustomClaim(`${namespace}/phone_number`, event.user.phone_number);
  }
};
```

### Scripted Actions (Management API)

Alongside the declarative block above, the mock runs real Action code. A
controller built on `go-auth0` (or plain HTTP) creates, deploys, and binds
Actions exactly as against a tenant, and the deployed JavaScript runs at the
`post-login` trigger on the `authorization_code` and `refresh_token` flows.

```sh
# create (built synchronously), deploy, bind
curl -X POST http://localhost:3000/api/v2/actions/actions \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer x' \
  -d '{"name":"guardian-approval","runtime":"node22",
       "supported_triggers":[{"id":"post-login","version":"v3"}],
       "secrets":[{"name":"HOOK","value":"http://api:8080/v1/auth/hooks/post-login"}],
       "code":"exports.onExecutePostLogin = async (event, api) => { const r = await fetch(event.secrets.HOOK, {method:\"POST\", body: JSON.stringify({user_id: event.user.user_id, device_id: event.request.query.device_id})}); const d = await r.json(); if (d.decision === \"deny\") api.access.deny(d.reason); };"}'
curl -X POST http://localhost:3000/api/v2/actions/actions/<id>/deploy -H 'Authorization: Bearer x'
curl -X PATCH http://localhost:3000/api/v2/actions/triggers/post-login/bindings \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer x' \
  -d '{"bindings":[{"ref":{"type":"action_name","value":"guardian-approval"}}]}'
```

Endpoints: `GET /api/v2/actions/triggers`; `GET|POST /api/v2/actions/actions`
(filters `actionName`, `triggerId`, `deployed`); `GET|PATCH|DELETE
/api/v2/actions/actions/{id}` (`?force=true` unbinds first); `POST
/api/v2/actions/actions/{id}/deploy`; `GET /api/v2/actions/actions/{id}/versions`;
`GET|PATCH /api/v2/actions/triggers/{trigger}/bindings` (refs by `action_id`,
`action_name`, or `binding_id`; the list replaces the order). Secret values are
write-only, as in Auth0. Nothing persists across restarts: reconcile on startup.

What the code gets: `event` (`user` with `app_metadata`/`user_metadata`,
`client`, `connection`, `request` with the `/authorize` `query` and the token
`body`, `transaction`, `organization`, `secrets`), `api.idToken.setCustomClaim`,
`api.accessToken.setCustomClaim`, `api.access.deny(reason)`,
`api.user.setAppMetadata`/`setUserMetadata`, `console`, and a global `fetch`
(Promise API; `ok`, `status`, `headers.get`, `json()`, `text()`). `require` is
not available: npm dependencies are not installed here. A denied login answers
the token request with `403 {"error":"access_denied","error_description":...}`;
a throwing Action does the same with the error. Runs are bounded at 20 seconds.
Bound but undeployed Actions do not run. Engine: [goja](https://github.com/dop251/goja).

## Management API

### Organizations

```bash
# List organizations
GET /api/v2/organizations

# Get organization
GET /api/v2/organizations/:id

# Create organization
POST /api/v2/organizations
{
  "name": "my-org",
  "display_name": "My Organization"
}

# Update organization
PATCH /api/v2/organizations/:id
{
  "display_name": "Updated Name"
}

# Delete organization
DELETE /api/v2/organizations/:id

# List members
GET /api/v2/organizations/:id/members

# Add members
POST /api/v2/organizations/:id/members
{
  "members": [
    {
      "user_id": "auth0|user_1",
      "roles": ["admin"]
    },
    {
      "user_id": "auth0|user_2",
      "roles": ["member"]
    }
  ]
}
```

### Connections

```bash
# List connections
GET /api/v2/connections

# Create connection
POST /api/v2/connections
{
  "name": "my-connection",
  "strategy": "oidc",
  "display_name": "Enterprise SSO"
}
```

### Users

```bash
# Get user
GET /api/v2/users/:id

# Update user metadata
PATCH /api/v2/users/:id
{
  "app_metadata": {
    "tenant_id": "org_1",
    "role": "admin"
  },
  "user_metadata": {
    "preferences": {}
  }
}
```

### Log streams

```bash
GET|POST /api/v2/log-streams
GET|PATCH|DELETE /api/v2/log-streams/:id
```

All eight stream types are accepted and validated against Auth0's Management API schemas, with
`pii_config` and `startFrom`. Only `http` (custom webhook) streams deliver; `pii_config` is stored, not
applied to delivered records. The mock emits:

| Event | Type | When |
|---|---|---|
| Successful login | `s` | the code is exchanged and post-login Actions allow it |
| Failed login | `f` | wrong code, refused invitation, non-member organization, post-login deny |
| Token exchange | `secte` / `fecte` | custom token exchange succeeds / fails |

Each active stream whose category filters match receives the record as `{log_id, data}` in its
content format (`JSONLINES`, `JSONARRAY`, or `JSONOBJECT` as `{"logs": [...]}`), with its
`httpAuthorization` and custom headers. The endpoint must be `https`. A non-2xx answer is retried up to
three times. To deliver to a
receiver behind a locally issued certificate, set `logStreamCAFile` in config, or
`logStreamCA.secretName` in the chart. The file is read on each delivery, so it may appear or
rotate after the mock starts; until it can be read, deliveries fail and are retried.

### Users

```bash
POST /api/v2/users
GET /api/v2/users-by-email?email=...
POST /api/v2/users/:id/identities
```

Users are created on passwordless connections only, as `email|...` or `sms|...`. A sign-in through an
enterprise connection (the `connection` authorize parameter) finds or provisions that connection's
user, as `<strategy>|<connection>|...`. A passwordless sign-in prefers the user holding a
passwordless identity for the address, so after a link it lands on the primary. Linking deletes the
secondary user and its memberships. `link_with` is not implemented.

### Self-Service SSO

```bash
GET|POST /api/v2/self-service-profiles
GET|PATCH|DELETE /api/v2/self-service-profiles/:id
POST /api/v2/self-service-profiles/:id/sso-ticket
POST /api/v2/self-service-profiles/:id/sso-ticket/:ticket/revoke
GET|POST /self-service/connections-flow?ticket=...
```

A ticket names either `connection_config` (create a connection) or `connection_id` (edit one). Its
link opens a form for the strategy, display name and email domains. Finishing it creates or edits
the connection, enables it for the ticket's clients and organizations, and spends the ticket. Every
domain is treated as verified. Ticket fields the mock cannot apply are refused with 400.

## OIDC Endpoints

- `/.well-known/openid-configuration` - Discovery
- `/.well-known/jwks.json` - JSON Web Key Set
- `/authorize` - Authorization endpoint
- `/oauth/token` - Token endpoint
- `/userinfo` - UserInfo endpoint
- `/v2/logout` - Logout endpoint

## Integration

### Docker Compose

See `examples/docker-compose.yml` for integration example.

### Kubernetes

See `examples/kubernetes.yaml` for raw Kubernetes manifests.

### Helm Chart

```bash
helm install auth0 ./charts/auth0 \
  --set config.issuer=https://auth.example.com/ \
  --set config.audience=https://api.example.com
```

## Testing

```bash
# Run all tests
just ci

# Or directly
go test -v ./...

# With linting
golangci-lint run
```

Tests cover:
- Complete OAuth2/OIDC flows with PKCE
- SMS and email authentication
- Custom claims in tokens
- Management API endpoints
- CORS headers
- Token validation
- Error cases

## Building

```bash
# Local binary
go build -o bin/auth0 ./cmd

# Docker image
docker build -t auth0:dev .

# Multi-arch (via CI)
# Automatically builds for linux/amd64 and linux/arm64
```

## Use Cases

- **Local Development**: Replace Auth0 in development environments
- **Testing**: Automated testing without external dependencies
- **CI/CD**: Integration tests with full OIDC flow
- **Demos**: Quick setup for proof-of-concepts
- **Multi-Tenancy Testing**: Test organization and role-based access control

## Differences from Real Auth0

This is a mock service for development and testing. Key differences:

1. **No Actual SMS/Email**: Verification code is always `123456` in development
2. **No Password Storage**: This is passwordless-only
3. **In-Memory Storage**: Data is not persisted
4. **Simplified API**: Only essential Management API endpoints
5. **No Rate Limiting**: Unlimited requests
6. **No Production Security**: Use only for development/testing

## License

See [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Ensure `just ci` passes
5. Submit a pull request

## Architecture

- **Go 1.24+** with standard library HTTP server
- **JWT**: RS256 signing with dynamically generated keys
- **OIDC**: Full compliance with OpenID Connect Core 1.0
- **Storage**: In-memory maps with mutex synchronization
- **Testing**: httptest with oidc-go verification

## Support

For issues, feature requests, or questions:
- GitHub Issues: https://github.com/46labs/auth0/issues
- Documentation: This README

## Roadmap

- [ ] SAML connection support
- [x] Actions: declarative `post_login` trigger (custom claim shaping)
- [x] Actions: scripted `post-login` Actions through the Management API (create, deploy, bind; `fetch`, `deny`, metadata)
- [ ] Actions: run code at `credentials-exchange`, `post-user-registration`, `custom-token-exchange`
- [ ] Persistent storage option
- [ ] WebAuthn/Passkey support
- [ ] Social connection mocks
- [ ] MFA simulation
