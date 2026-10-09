.PHONY: build test docker-test

VERSION ?= $(shell cat VERSION)
LDFLAGS := $(if $(VERSION),-X github.com/brodyhoskins/mailcloak/internal/version.Version=$(VERSION))

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o . ./cmd/...

test:
	go test ./...

# End-to-end tests against real Postfix (see docker-compose.yml).
# KEEP=1 leaves the environment running; Mailpit UI on http://localhost:8025.
docker-test:
	VERSION=$(VERSION) docker compose up -d --build
	docker compose exec -T postfix run-tests.sh || { docker compose logs --tail 80 postfix; $(if $(KEEP),,docker compose down -v;) exit 1; }
	$(if $(KEEP),,docker compose down -v)
