#!/bin/sh
set -eu

OS="${OPENSEARCH_URL:-http://opensearch:9200}"
BOOT="${BOOTSTRAP_DIR:-/bootstrap}"

echo "waiting for OpenSearch at $OS ..."
until curl -sf "$OS/_cluster/health?wait_for_status=yellow&timeout=60s" >/dev/null; do
  sleep 2
done

echo "install index template keeppam-audit ..."
curl -sf -X PUT "$OS/_index_template/keeppam-audit" \
  -H "Content-Type: application/json" \
  --data-binary "@$BOOT/index-template.json"

echo "install ISM policy keeppam-audit-retention ..."
if curl -sf -X PUT "$OS/_plugins/_ism/policies/keeppam-audit-retention" \
  -H "Content-Type: application/json" \
  --data-binary "@$BOOT/ism-policy.json"; then
  echo "ISM ok"
else
  echo "ISM policy skipped (plugin unavailable)"
fi

echo "opensearch bootstrap done"
