#!/usr/bin/env bash
# Build an air-gapped update bundle: docker save + checksums + manifest.
# Usage: SET=core|full ./scripts/keeppam-pack.sh [outdir]
# Run on a connected build host after `make up` (images exist locally).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SET="${SET:-core}"
OUT="${1:-$ROOT/dist}"
VER="$(tr -d ' \n' < "$ROOT/VERSION")"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="keeppam-${VER}-offline-${SET}"
STAGE="$OUT/$NAME"
mkdir -p "$STAGE"

mapfile -t IMAGES < <("$ROOT/scripts/keeppam-images.sh")
MISSING=0
for img in "${IMAGES[@]}"; do
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    echo "missing image: $img" >&2
    MISSING=1
  fi
done
if [[ "$MISSING" -ne 0 ]]; then
  echo "Build/pull images first (make up). Abort." >&2
  exit 1
fi

echo "== docker save ${#IMAGES[@]} images =="
docker save "${IMAGES[@]}" -o "$STAGE/images.tar"

{
  echo "KeepPAM offline bundle"
  echo "version=$VER"
  echo "set=$SET"
  echo "created=$TS"
  echo "host=$(hostname -f 2>/dev/null || hostname)"
  echo
  echo "images:"
  for img in "${IMAGES[@]}"; do
    id="$(docker image inspect -f '{{.Id}}' "$img")"
    echo "  $img  $id"
  done
} > "$STAGE/MANIFEST.txt"

cp "$ROOT/VERSION" "$STAGE/VERSION"
cp "$ROOT/NOTICE" "$STAGE/NOTICE"
"$ROOT/scripts/keeppam-images.sh" > "$STAGE/images.txt"

echo "== copy install tree =="
mkdir -p "$STAGE/scripts" "$STAGE/docs" "$STAGE/services/auth" "$STAGE/deploy"
cp "$ROOT/scripts/keeppam-compose.inc.sh" \
  "$ROOT/scripts/keeppam-install.sh" \
  "$ROOT/scripts/keeppam-upgrade.sh" \
  "$ROOT/scripts/keeppam-rollback.sh" \
  "$ROOT/scripts/keeppam-retag.sh" \
  "$ROOT/scripts/keeppam-images.sh" \
  "$ROOT/scripts/keeppam-version.sh" \
  "$ROOT/scripts/keeppam-dist.sh" \
  "$ROOT/scripts/backup.sh" \
  "$ROOT/scripts/restore.sh" \
  "$STAGE/scripts/"
chmod +x "$STAGE/scripts/"*.sh
cp "$ROOT/docs/offline-update.txt" "$ROOT/docs/install.txt" "$ROOT/docs/demo-45min.txt" "$ROOT/docs/runtime-brand.txt" "$ROOT/docs/license.txt" "$ROOT/docs/system-requirements.txt" "$STAGE/docs/"
cp -a "$ROOT/services/auth/migrations" "$STAGE/services/auth/"
cp "$ROOT/deploy/docker-compose.yml" "$ROOT/deploy/compose.ha.yml" "$ROOT/deploy/compose.ha3.yml" \
  "$ROOT/deploy/compose.branded.yml" "$ROOT/deploy/compose.branded-ha.yml" \
  "$ROOT/deploy/image-brand-map.txt" \
  "$ROOT/deploy/.env.example" "$ROOT/deploy/images-core.txt" "$ROOT/deploy/images-full.txt" \
  "$STAGE/deploy/"
if [[ -f "$ROOT/deploy/Dockerfile.api" ]]; then
  cp "$ROOT/deploy/Dockerfile.api" "$STAGE/deploy/"
fi
if [[ -f "$ROOT/VERSION_HISTORY" ]]; then
  cp "$ROOT/VERSION_HISTORY" "$STAGE/VERSION_HISTORY"
fi
for d in opa geoip demo-postgres demo-ssh prometheus grafana otel-collector tempo alertmanager opensearch ha pades; do
  if [[ -d "$ROOT/deploy/$d" ]]; then
    cp -a "$ROOT/deploy/$d" "$STAGE/deploy/"
  fi
done
if [[ -f "$ROOT/deploy/auth-server" ]]; then
  cp "$ROOT/deploy/auth-server" "$STAGE/deploy/auth-server"
fi
cat > "$STAGE/install.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec ./scripts/keeppam-install.sh "$@"
EOF
chmod +x "$STAGE/install.sh"

( cd "$STAGE" && sha256sum images.tar MANIFEST.txt VERSION NOTICE images.txt > SHA256SUMS )

TARBALL="$OUT/${NAME}.tar.gz"
tar -C "$OUT" -czf "$TARBALL" "$NAME"
( cd "$OUT" && sha256sum "$(basename "$TARBALL")" > "${NAME}.tar.gz.sha256" )

echo "bundle=$TARBALL"
echo "dir=$STAGE"
echo "Copy the .tar.gz (and .sha256) to USB/ISO."
echo "Install: tar xzf … && cd keeppam-… && ./install.sh"
echo "Upgrade existing: scripts/keeppam-upgrade.sh $TARBALL"
