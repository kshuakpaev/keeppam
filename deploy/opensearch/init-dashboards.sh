#!/bin/sh
set -eu

OSD="${DASHBOARDS_URL:-http://opensearch-dashboards:5601}"
BOOT="${BOOTSTRAP_DIR:-/bootstrap}/dashboard"

hdr() {
  echo "-H" "Content-Type: application/json"
  echo "-H" "osd-xsrf: true"
}

echo "waiting for OpenSearch Dashboards at $OSD ..."
until curl -sf "$OSD/api/status" >/dev/null; do
  sleep 3
done

put_obj() {
  type=$1
  id=$2
  file=$3
  echo "saved object $type/$id ..."
  curl -sf -X POST "$OSD/api/saved_objects/$type/$id?overwrite=true" \
    -H "Content-Type: application/json" \
    -H "osd-xsrf: true" \
    --data-binary "@$file"
}

put_obj index-pattern keeppam-audit-pattern "$BOOT/index-pattern.json"
put_obj visualization keeppam-audit-timeline "$BOOT/viz-timeline.json"
put_obj visualization keeppam-audit-actions "$BOOT/viz-actions.json"
put_obj dashboard keeppam-audit "$BOOT/dashboard.json"

echo "dashboards bootstrap done"
