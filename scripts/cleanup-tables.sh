#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════
#  SpyCloud Sentinel — Delete Old Tables Before Redeployment
#  
#  Use this when redeploying with schema changes. Deletes existing
#  SpyCloud custom tables so the ARM template can recreate them
#  with the updated schema.
#  
#  WARNING: This deletes all data in these tables. Only run before
#  a fresh deployment or when you need to update table schemas.
#
#  Usage: ./scripts/cleanup-tables.sh -g <resource-group> -w <workspace>
#═══════════════════════════════════════════════════════════════════
set -uo pipefail
RG=""; WS=""
while [[ $# -gt 0 ]]; do
  case $1 in -g) RG="$2"; shift 2;; -w) WS="$2"; shift 2;; *) shift;; esac
done
[[ -z "$RG" || -z "$WS" ]] && { echo "Usage: $0 -g <resource-group> -w <workspace>"; exit 1; }

az account show &>/dev/null || az login

echo "Deleting SpyCloud custom tables from workspace: $WS"
echo "WARNING: This removes all data in these tables."
echo ""

for TABLE in \
  SpyCloudBreachWatchlist_CL \
  SpyCloudBreachCatalog_CL \
  SpyCloudCompassData_CL \
  SpyCloudCompassDevices_CL \
  Spycloud_MDE_Logs_CL \
  SpyCloud_ConditionalAccessLogs_CL; do
  
  echo -n "  $TABLE: "
  az monitor log-analytics workspace table delete \
    --resource-group "$RG" --workspace-name "$WS" --name "$TABLE" \
    2>/dev/null && echo "deleted" || echo "not found (ok)"
done

echo ""
echo "Also deleting DCR and DCE (will be recreated)..."
DCR_NAME="dcr-sc-$(echo "$WS" | head -c 30)"
DCE_NAME="dce-spycloud-$(echo "$WS" | head -c 30)"

az monitor data-collection rule delete --name "$DCR_NAME" -g "$RG" --yes 2>/dev/null && echo "  DCR deleted" || echo "  DCR not found (ok)"
az monitor data-collection endpoint delete --name "$DCE_NAME" -g "$RG" --yes 2>/dev/null && echo "  DCE deleted" || echo "  DCE not found (ok)"

echo ""
echo "Done. Now redeploy with Deployment Mode = Full."
