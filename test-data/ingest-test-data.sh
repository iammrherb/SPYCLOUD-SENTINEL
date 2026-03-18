#!/bin/bash
# SpyCloud Test Data Ingestion via Azure Monitor Data Collection API
# Usage: ./ingest-test-data.sh -e <DCE_ENDPOINT> -r <DCR_IMMUTABLE_ID>

DCE_ENDPOINT="${1:-$DCE_ENDPOINT}"
DCR_ID="${2:-$DCR_IMMUTABLE_ID}"
TOKEN=$(az account get-access-token --resource https://monitor.azure.com --query accessToken -o tsv)

for TABLE in SpyCloudBreachWatchlist_CL SpyCloudBreachCatalog_CL SpyCloudCompassData_CL SpyCloudCompassDevices_CL SpyCloudCompassApplications_CL SpyCloudSipCookies_CL Spycloud_MDE_Logs_CL SpyCloud_ConditionalAccessLogs_CL SpyCloudIdentityExposure_CL SpyCloudExposure_CL SpyCloudInvestigations_CL SpyCloudIdLink_CL SpyCloudCAP_CL; do
  STREAM="Custom-$TABLE"
  FILE="test-data/$TABLE.json"
  [ ! -f "$FILE" ] && continue
  echo -n "  $TABLE: "
  curl -s -X POST "$DCE_ENDPOINT/dataCollectionRules/$DCR_ID/streams/$STREAM?api-version=2023-01-01" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d @"$FILE" \
    -o /dev/null -w "%{http_code}" && echo " ✅" || echo " ❌"
done
