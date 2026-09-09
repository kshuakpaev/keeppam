.PHONY: up down logs tidy api-run smoke acceptance-smoke geo-drill web-build api-build sbom geoip-mmdb pack dist bump install demo-seed

web-build:

web-build:
	cd web && npm install && npm run build

# Embed VERSION into the binary (override with VERSION=… or after keeppam-version.sh bump).
KEEPPAM_VERSION ?= $(shell tr -d ' \n' < VERSION 2>/dev/null || echo dev)
KEEPPAM_BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -X github.com/keeppam/auth/internal/buildinfo.Version=$(KEEPPAM_VERSION) -X github.com/keeppam/auth/internal/buildinfo.BuildTime=$(KEEPPAM_BUILD_TIME)

api-build:
	export PATH=/usr/local/go/bin:$$PATH && cd services/auth && CGO_ENABLED=0 GOOS=linux go build -ldflags "$(LDFLAGS)" -o ../../deploy/auth-server ./cmd/server

sbom:
	mkdir -p deploy/sbom
	export PATH=/usr/local/go/bin:$$PATH && cd services/auth && go run ./cmd/sbom > ../../deploy/sbom/keeppam-api.cdx.json

geoip-mmdb:
	mkdir -p deploy/geoip
	export PATH=/usr/local/go/bin:$$PATH && cd services/auth && go run ./cmd/geoip-mmdb ../../deploy/geoip/country-demo.mmdb

# Сборка на хосте — без pull golang/node из Docker Hub (офлайн / IPv6).
up: api-build web-build
	docker compose -f deploy/docker-compose.yml build web demo-ssh
	docker compose -f deploy/docker-compose.yml --profile build build iso-browser rdp-jump
	docker compose -f deploy/docker-compose.yml --profile obs up -d
	docker compose -f deploy/docker-compose.yml --profile obs restart api session-worker
	# nginx caches upstream IPs unless using Docker DNS variables — recreate web after api restart
	docker compose -f deploy/docker-compose.yml up -d --force-recreate web

logs:
	docker compose -f deploy/docker-compose.yml logs -f api session-worker web

tidy:
	cd services/auth && go mod tidy

api-run:
	cd services/auth && \
	KEEPPAM_DATA_KEY=a2VlcHBhbS1sb2NhbC1kZXYta2V5LTMyLWJ5dGVzISE= \
	KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD='ChangeMeNow!1' \
	KEEPPAM_CORS_ORIGIN=http://localhost:5173 \
	go run -ldflags "$(LDFLAGS)" ./cmd/server

smoke:
	./scripts/smoke.sh

acceptance-smoke:
	./scripts/kp-acceptance-smoke.sh

geo-drill:
	./scripts/geo-drill.sh

pack:
	./scripts/keeppam-pack.sh

# Полная сборка дистрибутива (авто +1 patch к VERSION, затем бинарники + образы + tar.gz).
# BUMP=minor|major|none|patch  (default patch)
dist:
	./scripts/keeppam-dist.sh

bump:
	./scripts/keeppam-version.sh bump

install:
	./scripts/keeppam-install.sh

demo-seed:
	./scripts/demo-seed.sh
