# auth0

OIDC provider for local development with SMS passwordless flow.

## Features

- OIDC discovery, JWKS, authorize, token, userinfo endpoints
- SMS passwordless with mock verification UI
- PKCE support
- Customizable login template

## Usage

```bash
just up    # Start local dev
just ci    # Run tests
just down  # Destroy dev env
```

## Configuration

All configuration via environment variables:

```bash
ISSUER=https://auth.46labs.test
AUDIENCE=https://api.46labs.test
PORT=3000
```

## Custom Login Template

Mount your HTML at `/config/login.html`:

```yaml
volumeMounts:
- name: custom-login
  mountPath: /config
volumes:
- name: custom-login
  configMap:
    name: my-login-template
```

Template must include `{{.SessionID}}` in the form.

## Endpoints

- `/.well-known/openid-configuration`
- `/.well-known/jwks.json`
- `/authorize`
- `/oauth/token`
- `/userinfo`
- `/v2/logout`
