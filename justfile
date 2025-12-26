set shell := ["bash", "-uc"]

default:
	@echo "Usage:"
	@echo "  just docker - Start with docker run"
	@echo "  just kind   - Start Kind cluster + Tilt"
	@echo "  just ci     - Run tests and lint"
	@echo "  just down   - Stop everything"

docker:
	@echo "Building..."
	docker build -t auth0:dev .
	@echo "Starting on http://localhost:4646"
	docker run --rm -d \
		--name auth0 \
		-p 4646:3000 \
		-e ISSUER=http://localhost:4646/ \
		-e AUDIENCE=https://localhost:3000 \
		auth0:dev
	@echo "Discovery: http://localhost:4646/.well-known/openid-configuration"

ci:
	@echo "Checking format..."
	@gofmt -l .
	@echo "Running tests..."
	@go test -v ./pkg/...
	@echo "Running linter..."
	@golangci-lint run

# Context safety check
_context-guard:
	#!/usr/bin/env bash
	set -euo pipefail

	CURRENT_CONTEXT=$(kubectl config current-context 2>/dev/null || echo "none")
	ALLOWED_CONTEXTS=("kind-auth0" "docker-desktop" "none")

	for allowed in "${ALLOWED_CONTEXTS[@]}"; do
		if [[ "$CURRENT_CONTEXT" == "$allowed" ]]; then
			exit 0
		fi
	done

	echo "ERROR: Current kubectl context '$CURRENT_CONTEXT' is not allowed"
	echo "Allowed contexts: ${ALLOWED_CONTEXTS[*]}"
	echo "Switch context or update ALLOWED_CONTEXTS in justfile"
	exit 1

kind: _context-guard
	#!/usr/bin/env bash
	set -euo pipefail

	if ! kind get clusters 2>/dev/null | grep -q "^auth0$"; then
		echo "Creating Kind cluster..."
		kind create cluster --config dev/kind-config.yaml
		kubectl config use-context kind-auth0

		echo "Installing nginx-ingress..."
		helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx 2>/dev/null || true
		helm repo update
		helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
			--namespace ingress-nginx --create-namespace \
			--set controller.service.type=NodePort \
			--set controller.service.nodePorts.http=30080 \
			--set controller.service.nodePorts.https=30443 \
			--set controller.ingressClassResource.default=true \
			--wait --timeout=5m

		echo "Setting up TLS certs..."
		just _setup-certs

		echo "Setting up /etc/hosts..."
		just _setup-hosts
	else
		echo "Kind cluster exists"
		kubectl config use-context kind-auth0
	fi

	echo "Starting Tilt..."
	tilt up

_setup-certs:
	#!/usr/bin/env bash
	set -euo pipefail
	mkdir -p dev/certs
	if [[ -f dev/certs/tls.crt ]]; then
		echo "Certs exist"
		exit 0
	fi
	echo "Generating TLS certs with mkcert..."
	if ! command -v mkcert &>/dev/null; then
		echo "ERROR: mkcert not found. Install with: brew install mkcert"
		exit 1
	fi
	mkcert -CAROOT &>/dev/null || mkcert -install
	cd dev/certs
	mkcert -cert-file tls.crt -key-file tls.key "*.46labs.test" "46labs.test"

_setup-hosts:
	#!/usr/bin/env bash
	set -euo pipefail
	ENTRY="127.0.0.1 auth.46labs.test api.46labs.test"
	if ! grep -q "auth.46labs.test" /etc/hosts 2>/dev/null; then
		echo "Adding to /etc/hosts: $ENTRY"
		echo "$ENTRY" | sudo tee -a /etc/hosts >/dev/null || echo "Failed - add manually"
	else
		echo "/etc/hosts already configured"
	fi

down:
	@echo "Stopping..."
	docker stop auth0 2>/dev/null || true
	tilt down 2>/dev/null || true
	kind delete cluster --name auth0 2>/dev/null || true
