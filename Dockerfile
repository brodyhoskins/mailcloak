# syntax=docker/dockerfile:1
#
# Test image: Alpine's Postfix with mailcloak wired in as pipe-mode content
# filters, plus GnuPG/OpenSSL test identities. Not for production use.
# See docker-compose.yml; `make docker-test` runs the end-to-end tests.

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "${VERSION:+-X github.com/brodyhoskins/mailcloak/internal/version.Version=$VERSION}" \
      -o /out/ ./cmd/...

FROM alpine:3
RUN apk add --no-cache postfix gnupg openssl curl jq \
 && addgroup -S mailcloak \
 && adduser -S -D -H -G mailcloak -h /var/lib/mailcloak -s /sbin/nologin mailcloak \
 && install -d -o mailcloak -g mailcloak -m 0750 /var/lib/mailcloak /var/log/mailcloak

COPY --from=build /out/ /usr/local/bin/
COPY data/mailcloak.yaml /etc/mailcloak/mailcloak.yaml
COPY data/setup-postfix.sh data/gen-keys.sh data/entrypoint.sh data/run-tests.sh /usr/local/sbin/
RUN setup-postfix.sh && gen-keys.sh

EXPOSE 25 587
ENTRYPOINT ["entrypoint.sh"]
