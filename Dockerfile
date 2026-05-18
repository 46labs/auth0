# Builder runs on the native host arch (BUILDPLATFORM). Go cross-compiles to
# the target arch via GOARCH=$TARGETARCH — no QEMU emulation needed.
# CGO_ENABLED=0 keeps the binary pure-Go, which is what makes cross-compile free.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETARCH

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -o /auth0 ./cmd

# Runtime stage is platform-specific (pulls alpine for the right arch);
# Docker handles that automatically based on the target platform.
FROM alpine:3.21
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /auth0 ./auth0
COPY --from=builder /build/templates ./templates
EXPOSE 3000
CMD ["./auth0"]
