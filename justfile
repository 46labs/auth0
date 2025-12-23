set shell := ["bash", "-uc"]

default:
	@echo "Usage:"
	@echo "  just up    - Start local dev"
	@echo "  just ci    - Run tests and lint"
	@echo "  just down  - Stop local dev"

up:
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
	@docker run --rm -v /home/jarrod/.local/dev/auth0:/app -w /app golang:1.24-alpine sh -c "gofmt -l ."
	@echo "Running tests..."
	@docker run --rm -v /home/jarrod/.local/dev/auth0:/app -w /app golang:1.24-alpine go test -v ./pkg/...
	@echo "Running linter..."
	@docker run --rm -v /home/jarrod/.local/dev/auth0:/app -w /app golangci/golangci-lint:latest golangci-lint run

down:
	docker stop auth0 || true
