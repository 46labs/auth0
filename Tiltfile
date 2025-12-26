load('ext://helm_resource', 'helm_resource')
load('ext://namespace', 'namespace_create')

allow_k8s_contexts('kind-auth0')

namespace_create('auth0')

update_settings(k8s_upsert_timeout_secs=120)

# TLS secret
local_resource(
    'tls-secret',
    cmd='''
    kubectl create namespace auth0 --dry-run=client -o yaml | kubectl apply -f - && \\
    kubectl get secret auth0-tls -n auth0 2>/dev/null || \\
    (test -f dev/certs/tls.crt && test -f dev/certs/tls.key && \\
    kubectl create secret tls auth0-tls -n auth0 \\
        --cert=dev/certs/tls.crt --key=dev/certs/tls.key || \\
    echo "ERROR: Run 'just kind' first to generate TLS certs")
    ''',
    labels=['setup'],
)

# Build auth0 image
docker_build(
    'ghcr.io/46labs/auth0',
    '.',
    dockerfile='./Dockerfile',
    live_update=[
        sync('./pkg', '/app/pkg'),
        sync('./cmd', '/app/cmd'),
        run('go build -o /app/auth0 cmd/main.go', trigger=['./go.mod', './go.sum']),
    ],
)

# Deploy with Helm
k8s_yaml(helm(
    './charts/auth0',
    name='auth0',
    namespace='auth0',
    set=[
        'service.type=ClusterIP',
        'ingress.enabled=true',
        'ingress.host=auth.46labs.test',
        'ingress.tls.enabled=true',
        'ingress.tls.secretName=auth0-tls',
        'config.issuer=https://auth.46labs.test/',
        'config.audience=https://api.46labs.test',
    ],
))

k8s_resource(
    'auth0',
    resource_deps=['tls-secret'],
    labels=['auth'],
)

# Health check
local_resource(
    'health-check',
    cmd='curl -sfk https://auth.46labs.test/.well-known/openid-configuration | jq .issuer || echo "Auth not ready"',
    auto_init=False,
    labels=['helpers'],
)
