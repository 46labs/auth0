# auth0

Full-featured OIDC provider mock with Auth0-compatible API for local development and testing.

## Features

### OIDC & OAuth2
- Complete OIDC/OAuth2 implementation (discovery, JWKS, authorize, token, userinfo)
- PKCE support
- SMS and email passwordless authentication
- Configurable custom claims with namespace support
- Multi-tenancy with organizations

### Auth0 Management API Mock
- Organizations CRUD (`/api/v2/organizations`)
- Connections management (`/api/v2/connections`)
- User metadata updates (`/api/v2/users/:id`)
- Organization membership management

### Developer Experience
- Dynamic login UI supporting both email and SMS
- Customizable branding and templates
- Configurable via YAML or environment variables
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
- [ ] Actions/Rules engine
- [ ] Persistent storage option
- [ ] WebAuthn/Passkey support
- [ ] Social connection mocks
- [ ] MFA simulation
