.PHONY: up down logs tidy api-run smoke acceptance-smoke geo-drill web-build api-build sbom geoip-mmdb pack install demo-seed

web-build:

web-build:
	cd web && npm install && npm run build

api-build:
	export PATH=/usr/local/go/bin:$$PATH && cd services/auth && CGO_ENABLED=0 GOOS=linux go build -o ../../deploy/auth-server ./cmd/server

sbom:
	mkdir -p deploy/sbom
	export PATH=/usr/local/go/bin:$$PATH && cd services/auth && go run ./cmd/sbom > ../../deploy/sbom/keeppam-api.cdx.json

geoip-mmdb:
	mkdir -p deploy/geoip
	export PATH=/usr/local/go/bin:$$PATH && cd services/auth && go run ./cmd/geoip-mmdb ../../deploy/geoip/country-demo.mmdb

# Сборка на хосте — без pull golang/node из Docker Hub (офлайн / IPv6).
up: api-build web-build
	docker compose -f deploy/docker-compose.yml build web demo-ssh
	docker compose -f deploy/docker-compose.yml --profile build build iso-browser
	docker compose -f deploy/docker-compose.yml --profile obs up -d
	docker compose -f deploy/docker-compose.yml --profile obs restart api session-worker

logs:
	docker compose -f deploy/docker-compose.yml logs -f api session-worker web

tidy:
	cd services/auth && go mod tidy

api-run:
	cd services/auth && \
	KEEPPAM_DATA_KEY=a2VlcHBhbS1sb2NhbC1kZXYta2V5LTMyLWJ5dGVzISE= \
	KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD='ChangeMeNow!1' \
	KEEPPAM_CORS_ORIGIN=http://localhost:5173 \
	go run ./cmd/server

smoke:
	./scripts/smoke.sh

acceptance-smoke:
	./scripts/kp-acceptance-smoke.sh

geo-drill:
	./scripts/geo-drill.sh

pack:
	./scripts/keeppam-pack.sh

install:
	./scripts/keeppam-install.sh

demo-seed:
	./scripts/demo-seed.sh
