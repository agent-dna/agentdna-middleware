# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.25-alpine AS build

WORKDIR /src

# Download dependencies first so this layer is cached unless go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

# Build a static binary (lib/pq is pure Go, so CGO can stay off).
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server .

# ---- runtime stage ----
FROM alpine:3.20

# ca-certificates: outbound TLS to the admin server and downstream Apps.
RUN apk add --no-cache ca-certificates \
	&& adduser -D -u 10001 app

WORKDIR /app
COPY --from=build /out/server /app/server

# SERVER_PORT is the only var with a sane default; DATABASE_URL, RUBIX_NODE_URL,
# JWT_SECRET and ADMIN_SERVICE_URL must be supplied at runtime.
ENV SERVER_PORT=8080
EXPOSE 8080

USER app
ENTRYPOINT ["/app/server"]
