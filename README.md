# auth0

OIDC provider for local development with SMS passwordless flow.

## Features

- Full OIDC implementation (discovery, JWKS, authorize, token, userinfo)
- SMS passwordless authentication with mock UI
- PKCE support
- Configurable via environment variables
- Customizable login template
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
just docker  # Runs on localhost:4646
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

Via environment variables:

```bash
ISSUER=https://auth.46labs.test/
AUDIENCE=https://api.46labs.test
PORT=3000
CORSORIGINS=https://app.example.com,https://admin.example.com
```

## Custom Login Template

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

Template must include `{{.SessionID}}` in form.

## Integration

See `examples/` for:
- `docker-compose.yml` - Docker Compose setup
- `kubernetes.yaml` - Raw Kubernetes manifests

Or use the Helm chart:

```bash
helm install auth0 ./charts/auth0 \
  --set config.issuer=https://auth.example.com/ \
  --set config.audience=https://api.example.com
```

## Endpoints

- `/.well-known/openid-configuration`
- `/.well-known/jwks.json`
- `/authorize`
- `/oauth/token`
- `/userinfo`
- `/v2/logout`
