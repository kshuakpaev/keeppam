#!/usr/bin/env bash
# End-to-end: build KeepPAM + pack offline distribution archive.
#
# Usage:
#   ./scripts/keeppam-dist.sh              # SET=core → dist/keeppam-<ver>-offline-core.tar.gz
#   SET=full ./scripts/keeppam-dist.sh    # + observability / HA images
#   OUT=/tmp/dist SKIP_PULL=1 ./scripts/keeppam-dist.sh
#   BUMP=patch|minor|major|none ./scripts/keeppam-dist.sh   # default: patch (+1)
#   SKIP_BUILD=1 ./scripts/keeppam-dist.sh # только упаковать уже собранные образы
#
# На другом сервере:
#   tar -xzf keeppam-*-offline-*.tar.gz && cd keeppam-* && ./install.sh
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SET="${SET:-core}"
OUT="${OUT:-$ROOT/dist}"
SKIP_PULL="${SKIP_PULL:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
# Auto-increment product version on each dist build (patch by default).
BUMP="${BUMP:-patch}"
export PATH="/usr/local/go/bin:${PATH:-}"

cd "$ROOT"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "need command: $1" >&2
    exit 1
  }
}

have_image() {
  docker image inspect "$1" >/dev/null 2>&1
}

need docker
need tar
need sha256sum

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon not available" >&2
  exit 1
fi

case "$SET" in
  core|full) ;;
  *)
    echo "SET must be core or full (got: $SET)" >&2
    exit 1
    ;;
esac

echo "== version bump (BUMP=$BUMP) =="
VER="$(BUMP="$BUMP" "$ROOT/scripts/keeppam-version.sh" bump)"
export KEEPPAM_VERSION="$VER"
echo "== KeepPAM dist SET=$SET version=$VER =="

if [[ "$SKIP_BUILD" != "1" ]]; then
  echo "== api-build =="
  need go
  make api-build KEEPPAM_VERSION="$VER"
  chmod +x "$ROOT/deploy/auth-server"

  echo "== web-build =="
  need npm
  make web-build

  echo "== ensure base alpine for API image =="
  if ! have_image alpine:3.21; then
    if [[ "$SKIP_PULL" == "1" ]]; then
      echo "missing alpine:3.21 (needed for deploy-api)" >&2
      exit 1
    fi
    docker pull alpine:3.21
  fi

  echo "== docker build deploy-api (host binary) =="
  docker build -t deploy-api:latest -f "$ROOT/deploy/Dockerfile.api" "$ROOT/deploy"

  echo "== docker build web / demo-ssh / firewall-probe =="
  if ! have_image nginx:alpine && [[ "$SKIP_PULL" != "1" ]]; then
    docker pull nginx:alpine
  fi
  docker compose -f "$ROOT/deploy/docker-compose.yml" build web demo-ssh firewall-probe

  if ! have_image keeppam-guacenc:1.5.5; then
    echo "== docker build guacenc (missing keeppam-guacenc:1.5.5) =="
    docker compose -f "$ROOT/deploy/docker-compose.yml" build guacenc
  else
    echo "== keeppam-guacenc:1.5.5 already present =="
  fi

  if [[ "$SET" == "full" ]]; then
    if ! have_image keeppam-iso-browser:local; then
      echo "== docker build iso-browser =="
      docker compose -f "$ROOT/deploy/docker-compose.yml" --profile build build iso-browser || true
    fi
  fi
else
  echo "== SKIP_BUILD=1 — using existing binaries/images =="
  if [[ ! -f "$ROOT/deploy/auth-server" ]]; then
    echo "missing deploy/auth-server (run without SKIP_BUILD or: make api-build)" >&2
    exit 1
  fi
fi

pull_if_missing() {
  local img="$1"
  if have_image "$img"; then
    return 0
  fi
  if [[ "$SKIP_PULL" == "1" ]]; then
    echo "missing image (SKIP_PULL=1): $img" >&2
    return 1
  fi
  echo "== docker pull $img =="
  docker pull "$img"
}

echo "== ensure bundle images =="
MISSING=0
while IFS= read -r img; do
  [[ -z "$img" ]] && continue
  if ! pull_if_missing "$img"; then
    MISSING=1
  fi
done < <(SET="$SET" "$ROOT/scripts/keeppam-images.sh")

if [[ "$MISSING" -ne 0 ]]; then
  echo "Some images are missing. Pull them or unset SKIP_PULL. Abort." >&2
  exit 1
fi

echo "== brand retag =="
"$ROOT/scripts/keeppam-retag.sh" || true

echo "== pack offline bundle =="
SET="$SET" "$ROOT/scripts/keeppam-pack.sh" "$OUT"

NAME="keeppam-${VER}-offline-${SET}"
TARBALL="$OUT/${NAME}.tar.gz"
cat > "$OUT/${NAME}.README.txt" <<EOF
KeepPAM ${VER} — offline distribution (${SET})

На сервере назначения (нужен Docker Engine + Compose plugin):

  tar -xzf ${NAME}.tar.gz
  cd ${NAME}
  ./install.sh

Портал: http://<host>:5173
API:    http://<host>:8080

Смените пароль в deploy/.env → KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD.
Лицензия: UI «Конфигурация → Лицензия KeepPAM».

Опции install.sh:
  KEEPPAM_HA=1 ./install.sh     # HA 2+2
  KEEPPAM_HA=3 ./install.sh     # HA 3+2
  KEEPPAM_OBS=1 ./install.sh    # Grafana/OpenSearch (для SET=full — само)

Документация в архиве: docs/install.txt, docs/offline-update.txt
EOF

echo
echo "OK archive: $TARBALL"
echo "OK readme:  $OUT/${NAME}.README.txt"
ls -lh "$TARBALL" "$OUT/${NAME}.tar.gz.sha256" 2>/dev/null || true
