# syntax=docker/dockerfile:1
# Build stage --------------------------------------------------------------
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Cache deps first.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static, stripped binary. CGO disabled so the result runs on scratch.
# -trimpath strips local filesystem paths from the binary (avoids leaking
# the build host's directory layout).
# -ldflags="-s -w" strips symbol and debug info — reduces forensic surface.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/spectre-relay ./

# Runtime stage ------------------------------------------------------------
FROM scratch

# Bring along CA roots so the binary can verify outbound TLS if it ever
# initiates any (defense in depth; current code does not).
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /out/spectre-relay /spectre-relay

# Run as a non-root numeric UID. No /etc/passwd in scratch, so we use a
# bare numeric uid:gid. 65532 is the conventional "nonroot" id.
USER 65532:65532

EXPOSE 443

ENTRYPOINT ["/spectre-relay"]
