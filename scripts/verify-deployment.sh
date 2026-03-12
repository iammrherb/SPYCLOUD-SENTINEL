#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# SpyCloud Sentinel Supreme — Deployment Verification & Validation
# Run this AFTER deployment to verify every component is configured
# Usage: ./verify-deployment.sh -g <resource-group> -w <workspace>
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

RG=""
WS=""
SUB=""
PASS=0
WARN=0
FAIL=0
PORTAL="https://portal.azure.com"

usage() {
  echo "Usage: $0 -g <resource-group> -w <workspace> [-s <subscription-id>]"
  exit 1
}

while getopts "g:w:s:" opt; do
  case $opt in
    g) RG="$OPTARG" ;;
    w) WS="$OPTARG" ;;
    s) SUB="$OPTARG" ;;
    *) usage ;;
  esac
done

[ -z "$RG" ] || [ -z "$WS" ] && usage

if [ -n "$SUB" ]; then
  az account set --subscription "$SUB" 2>/dev/null
fi
SUB=$(az account show --query id -o tsv 2>/dev/null)
TENANT=$(az account show --query tenantId -o tsv 2>/dev/null)
SUB_NAME=$(az account show --query name -o tsv 2>/dev/null)

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🛡️  SpyCloud Sentinel Supreme — Deployment Verification        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Subscription: ${BOLD}$SUB_NAME${NC} ($SUB)"
echo -e "  Tenant:       $TENANT"
echo -e "  RG:           ${BOLD}$RG${NC}"
echo -e "  Workspace:    ${BOLD}$WS${NC}"
echo -e "  Time:         $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo ""

pass() { ((PASS++)); echo -e "  ${GREEN}✅ PASS${NC} — $1"; }
warn() { ((WARN++)); echo -e "  ${YELLOW}⚠️  WARN${NC} — $1"; }
fail() { ((FAIL++)); echo -e "  ${RED}❌ FAIL${NC} — $1"; }
info() { echo -e "  ${BLUE}ℹ️  INFO${NC} — $1"; }
link() { echo -e "         ${CYAN}↗ $1${NC}"; }

# ═══════════════════════════════════════════════════════════════
# SECTION 1: WORKSPACE & SENTINEL
# ═══════════════════════════════════════════════════════════════
echo -e "${BOLD}═══ 1/10 WORKSPACE & SENTINEL ═══${NC}"

WS_ID=$(az monitor log-analytics workspace show --workspace-name "$WS" -g "$RG" --query id -o tsv 2>/dev/null || echo "")
if [ -n "$WS_ID" ]; then
  WS_LOC=$(az monitor log-analytics workspace show --workspace-name "$WS" -g "$RG" --query location -o tsv 2>/dev/null)
  WS_SKU=$(az monitor log-analytics workspace show --workspace-name "$WS" -g "$RG" --query "sku.name" -o tsv 2>/dev/null)
  WS_RET=$(az monitor log-analytics workspace show --workspace-name "$WS" -g "$RG" --query retentionInDays -o tsv 2>/dev/null)
  pass "Workspace '$WS' exists (region=$WS_LOC, sku=$WS_SKU, retention=${WS_RET}d)"
  link "$PORTAL/#@$TENANT/resource$WS_ID/overview"
else
  fail "Workspace '$WS' NOT FOUND in resource group '$RG'"
fi

# Check Sentinel is enabled
SENTINEL=$(az resource list -g "$RG" --resource-type "Microsoft.OperationsManagement/solutions" --query "[?contains(name,'SecurityInsights')].name" -o tsv 2>/dev/null || echo "")
if [ -n "$SENTINEL" ]; then
  pass "Microsoft Sentinel is enabled on workspace"
  link "$PORTAL/#blade/Microsoft_Azure_Security_Insights/MainMenuBlade/0/subscriptionId/$SUB/resourceGroup/$RG/workspaceName/$WS"
else
  fail "Microsoft Sentinel NOT enabled — install from Content Hub or create via Portal"
fi

# ═══════════════════════════════════════════════════════════════
# SECTION 2: DATA COLLECTION ENDPOINT (DCE)
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══ 2/10 DATA COLLECTION ENDPOINT (DCE) ═══${NC}"

DCE_NAME="dce-spycloud-$WS"
DCE_URI=$(az monitor data-collection endpoint show --name "$DCE_NAME" -g "$RG" --query "logsIngestion.endpoint" -o tsv 2>/dev/null || echo "")
if [ -n "$DCE_URI" ]; then
  DCE_ID=$(az monitor data-collection endpoint show --name "$DCE_NAME" -g "$RG" --query id -o tsv 2>/dev/null)
  pass "DCE '$DCE_NAME' exists"
  info "Ingestion URI: $DCE_URI"
  link "$PORTAL/#@$TENANT/resource$DCE_ID/overview"
else
  fail "DCE '$DCE_NAME' NOT FOUND"
  info "The CCF connector needs a DCE to receive data from SpyCloud API"
fi

# ═══════════════════════════════════════════════════════════════
# SECTION 3: DATA COLLECTION RULE (DCR)
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══ 3/10 DATA COLLECTION RULE (DCR) ═══${NC}"

DCR_NAME="dcr-spycloud-$WS"
DCR_IMMUTABLE=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" --query "immutableId" -o tsv 2>/dev/null || echo "")
if [ -n "$DCR_IMMUTABLE" ]; then
  DCR_ID=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" --query id -o tsv 2>/dev/null)
  STREAM_COUNT=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" --query "length(streamDeclarations)" -o tsv 2>/dev/null || echo "0")
  FLOW_COUNT=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" --query "length(dataFlows)" -o tsv 2>/dev/null || echo "0")
  pass "DCR '$DCR_NAME' exists (immutableId=$DCR_IMMUTABLE)"
  info "Streams: $STREAM_COUNT | Data Flows: $FLOW_COUNT"
  link "$PORTAL/#@$TENANT/resource$DCR_ID/overview"
  
  if [ "$STREAM_COUNT" -ge 4 ] 2>/dev/null; then
    pass "Primary DCR has $STREAM_COUNT streams (max 10 per DCR)"
  else
    warn "Primary DCR has $STREAM_COUNT streams (expected up to 10)"
  fi
else
  # DCR might have a different name (content template generates it)
  DCR_ALT=$(az monitor data-collection rule list -g "$RG" --query "[?contains(name,'pyCloud') || contains(name,'pycloud') || contains(name,'spycloud')].{name:name,id:immutableId}" -o tsv 2>/dev/null || echo "")
  if [ -n "$DCR_ALT" ]; then
    warn "DCR not found as '$DCR_NAME' but found alternatives:"
    echo "$DCR_ALT" | while read line; do info "  $line"; done
  else
    fail "No SpyCloud DCR found in resource group"
  fi
fi

# Extended DCR (Exposure, CAP, MDE Logs, CA Logs)
DCR_EXT_NAME="dcr-ccf-ext-$WS"
DCR_EXT_IMMUTABLE=$(az monitor data-collection rule show --name "$DCR_EXT_NAME" -g "$RG" --query "immutableId" -o tsv 2>/dev/null || echo "")
if [ -n "$DCR_EXT_IMMUTABLE" ]; then
  EXT_STREAM_COUNT=$(az monitor data-collection rule show --name "$DCR_EXT_NAME" -g "$RG" --query "length(streamDeclarations)" -o tsv 2>/dev/null || echo "0")
  EXT_FLOW_COUNT=$(az monitor data-collection rule show --name "$DCR_EXT_NAME" -g "$RG" --query "length(dataFlows)" -o tsv 2>/dev/null || echo "0")
  pass "Extended DCR '$DCR_EXT_NAME' exists (immutableId=$DCR_EXT_IMMUTABLE)"
  info "Extended DCR Streams: $EXT_STREAM_COUNT | Data Flows: $EXT_FLOW_COUNT"
else
  warn "Extended DCR '$DCR_EXT_NAME' not found — Exposure/CAP/MDE/CA streams may not be configured"
fi

# ═══════════════════════════════════════════════════════════════
# SECTION 4: CUSTOM TABLES
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══ 4/10 CUSTOM TABLES ═══${NC}"

EXPECTED_TABLES=("SpyCloudBreachWatchlist_CL" "SpyCloudBreachCatalog_CL" "Spycloud_MDE_Logs_CL" "SpyCloud_ConditionalAccessLogs_CL")
for TBL in "${EXPECTED_TABLES[@]}"; do
  TBL_INFO=$(az monitor log-analytics workspace table show --workspace-name "$WS" -g "$RG" --name "$TBL" --query "{plan:plan,retention:retentionInDays,cols:length(schema.columns)}" -o tsv 2>/dev/null || echo "")
  if [ -n "$TBL_INFO" ]; then
    PLAN=$(echo "$TBL_INFO" | cut -f1)
    RET=$(echo "$TBL_INFO" | cut -f2)
    COLS=$(echo "$TBL_INFO" | cut -f3)
    pass "$TBL (${COLS} columns, ${RET}d retention, plan=$PLAN)"
  else
    fail "$TBL — TABLE NOT FOUND"
    info "This table should be created by the content template during deployment"
  fi
done

# ═══════════════════════════════════════════════════════════════
# SECTION 5: DATA CONNECTOR
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══ 5/10 SPYCLOUD DATA CONNECTOR ═══${NC}"

CONNECTOR_DEF=$(az rest --method GET \
  --uri "https://management.azure.com$WS_ID/providers/Microsoft.SecurityInsights/dataConnectorDefinitions?api-version=2022-09-01-preview" \
  --query "value[?contains(name,'SpyCloud')].{name:name,kind:kind}" -o tsv 2>/dev/null || echo "")
if [ -n "$CONNECTOR_DEF" ]; then
  pass "SpyCloud connector definition exists"
else
  warn "SpyCloud connector definition not found via API (may need portal check)"
fi

CONNECTORS=$(az rest --method GET \
  --uri "https://management.azure.com$WS_ID/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-12-01-preview" \
  --query "value[?contains(properties.connectorDefinitionName || '','SpyCloud')].{name:name,kind:kind}" -o tsv 2>/dev/null || echo "")
if [ -n "$CONNECTORS" ]; then
  CONN_COUNT=$(echo "$CONNECTORS" | wc -l)
  pass "SpyCloud data connector(s) ACTIVE ($CONN_COUNT pollers connected)"
else
  warn "SpyCloud data connector NOT YET ACTIVATED"
  info "Go to Sentinel → Data connectors → SpyCloud → Open connector page → Connect"
  link "$PORTAL/#blade/Microsoft_Azure_Security_Insights/DataConnectorsListBlade/subscriptionId/$SUB/resourceGroup/$RG/workspaceName/$WS"
fi

# ═══════════════════════════════════════════════════════════════
# SECTION 6: KEY VAULT
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══ 6/10 KEY VAULT ═══${NC}"

KV=$(az keyvault list -g "$RG" --query "[?contains(name,'spycloud') || contains(name,'spytel')].{name:name,uri:properties.vaultUri}" -o tsv 2>/dev/null || echo "")
if [ -n "$KV" ]; then
  KV_NAME=$(echo "$KV" | head -1 | cut -f1)
  KV_URI=$(echo "$KV" | head -1 | cut -f2)
  pass "Key Vault '$KV_NAME' exists ($KV_URI)"
  
  SECRET=$(az keyvault secret show --vault-name "$KV_NAME" --name "spycloud-api-key" --query "name" -o tsv 2>/dev/null || echo "")
  if [ -n "$SECRET" ]; then
    pass "API key secret 'spycloud-api-key' exists in vault"
  else
    warn "API key secret not found in Key Vault"
  fi
else
  warn "No SpyCloud Key Vault found (optional but recommended)"
fi

# ═══════════════════════════════════════════════════════════════
# SECTION 7: LOGIC APP PLAYBOOKS
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══ 7/10 LOGIC APP PLAYBOOKS ═══${NC}"

PLAYBOOKS=("SpyCloud-MDE-Remediation-$WS" "SpyCloud-CA-Remediation-$WS" "SpyCloud-CredResponse-$WS" "SpyCloud-MDE-Blocklist-$WS")
PLAYBOOK_DESC=("MDE Device Isolation" "CA Identity Protection" "Credential Response + Teams" "MDE Blocklist (Scheduled)")

for i in "${!PLAYBOOKS[@]}"; do
  PB="${PLAYBOOKS[$i]}"
  DESC="${PLAYBOOK_DESC[$i]}"
  PB_INFO=$(az logic workflow show --name "$PB" -g "$RG" --query "{state:state,pid:identity.principalId,id:id}" -o tsv 2>/dev/null || echo "")
  if [ -n "$PB_INFO" ]; then
    STATE=$(echo "$PB_INFO" | cut -f1)
    PID=$(echo "$PB_INFO" | cut -f2)
    PB_ID=$(echo "$PB_INFO" | cut -f3)
    pass "$DESC: '$PB' (state=$STATE)"
    info "Managed Identity Object ID: $PID"
    link "$PORTAL/#@$TENANT/resource$PB_ID/logicApp"
    
    # Check if managed identity has any app role assignments
    ROLES=$(az rest --method GET \
      --uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='fc780465-2017-40d4-a0c5-307022471b92')/appRoleAssignedTo?\$filter=principalId eq '$PID'" \
      --query "value[].appRoleId" -o tsv 2>/dev/null || echo "")
    if [ -n "$ROLES" ]; then
      ROLE_COUNT=$(echo "$ROLES" | wc -l)
      pass "  → $ROLE_COUNT MDE API permission(s) assigned"
    else
      if [[ "$DESC" == *"MDE"* ]]; then
        warn "  → No MDE API permissions found — grant admin consent"
        info "  Entra ID → Enterprise Apps → Managed Identities → '$PB' → Permissions → Grant consent"
      fi
    fi
  else
    warn "$DESC: '$PB' NOT FOUND (may be disabled in deployment)"
  fi
done

# ═══════════════════════════════════════════════════════════════
# SECTION 8: ANALYTICS RULES
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══ 8/10 ANALYTICS RULES ═══${NC}"

RULES=$(az rest --method GET \
  --uri "https://management.azure.com$WS_ID/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01" \
  --query "value[?contains(properties.displayName || '','SpyCloud')].{name:properties.displayName,enabled:properties.enabled,severity:properties.severity}" -o json 2>/dev/null || echo "[]")

RULE_COUNT=$(echo "$RULES" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
ENABLED_COUNT=$(echo "$RULES" | python3 -c "import json,sys; print(sum(1 for r in json.load(sys.stdin) if r.get('enabled')))" 2>/dev/null || echo "0")

if [ "$RULE_COUNT" -gt 0 ] 2>/dev/null; then
  pass "$RULE_COUNT SpyCloud analytics rules deployed ($ENABLED_COUNT enabled)"
  link "$PORTAL/#blade/Microsoft_Azure_Security_Insights/AnalyticsConfigBlade/subscriptionId/$SUB/resourceGroup/$RG/workspaceName/$WS"
  if [ "$ENABLED_COUNT" -eq 0 ]; then
    warn "All rules are DISABLED — enable rules to start generating incidents"
    info "Recommended first: Infostealer Exposure, Plaintext Password, Session Cookies, Data Health"
  fi
else
  warn "No SpyCloud analytics rules found"
fi

# ═══════════════════════════════════════════════════════════════
# SECTION 9: WORKBOOK DASHBOARD
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══ 9/10 WORKBOOK DASHBOARD ═══${NC}"

WORKBOOKS=$(az rest --method GET \
  --uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Insights/workbooks?api-version=2022-04-01" \
  --query "value[?contains(properties.displayName || '','SpyCloud')].{name:properties.displayName,id:id}" -o tsv 2>/dev/null || echo "")
if [ -n "$WORKBOOKS" ]; then
  WB_NAME=$(echo "$WORKBOOKS" | head -1 | cut -f1)
  WB_ID=$(echo "$WORKBOOKS" | head -1 | cut -f2)
  pass "Workbook '$WB_NAME' deployed"
  link "$PORTAL/#@$TENANT/resource$WB_ID"
  info "Also visible: Sentinel → Workbooks → My workbooks"
else
  warn "No SpyCloud workbook found"
fi

# ═══════════════════════════════════════════════════════════════
# SECTION 10: DEPLOYMENT SCRIPT RESULTS
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══ 10/10 DEPLOYMENT SCRIPT ═══${NC}"

DS_STATUS=$(az deployment-scripts show --name "spycloud-post-deploy" -g "$RG" --query "provisioningState" -o tsv 2>/dev/null || echo "")
if [ -n "$DS_STATUS" ]; then
  if [ "$DS_STATUS" = "Succeeded" ]; then
    pass "Deployment script completed ($DS_STATUS)"
  else
    warn "Deployment script status: $DS_STATUS"
  fi
  info "View full logs:"
  info "  az deployment-scripts show-log --name spycloud-post-deploy -g $RG"
else
  warn "Deployment script 'spycloud-post-deploy' not found"
fi

# ═══════════════════════════════════════════════════════════════
# DATA FLOW CHECK
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══ DATA FLOW STATUS ═══${NC}"

for TBL in "SpyCloudBreachWatchlist_CL" "SpyCloudBreachCatalog_CL"; do
  ROW_COUNT=$(az monitor log-analytics query -w "$WS_ID" --analytics-query "$TBL | count" --query "[0].Count" -o tsv 2>/dev/null || echo "0")
  if [ "$ROW_COUNT" -gt 0 ] 2>/dev/null; then
    LATEST=$(az monitor log-analytics query -w "$WS_ID" --analytics-query "$TBL | summarize max(TimeGenerated)" --query "[0].max_TimeGenerated" -o tsv 2>/dev/null || echo "unknown")
    pass "$TBL: $ROW_COUNT records (latest: $LATEST)"
  else
    info "$TBL: 0 records — activate connector to start data flow"
  fi
done

# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  VERIFICATION SUMMARY                                           ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  ${GREEN}PASS: $PASS${NC}  |  ${YELLOW}WARN: $WARN${NC}  |  ${RED}FAIL: $FAIL${NC}                              ${CYAN}║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}                                                                ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${BOLD}Portal Links:${NC}                                                 ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Sentinel:    $PORTAL/#blade/Microsoft_Azure_Security_Insights/MainMenuBlade/0/subscriptionId/$SUB/resourceGroup/$RG/workspaceName/$WS"
echo -e "${CYAN}║${NC}  Connectors:  ...DataConnectorsListBlade (search SpyCloud)     ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Analytics:   ...AnalyticsConfigBlade (filter SpyCloud)        ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Workbooks:   Sentinel → Workbooks → My workbooks             ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Entra Apps:  Entra ID → Enterprise Apps → Managed Identities ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}                                                                ${CYAN}║${NC}"

if [ "$FAIL" -gt 0 ]; then
  echo -e "${CYAN}║${NC}  ${RED}ACTION REQUIRED: Fix $FAIL failed check(s) above${NC}                ${CYAN}║${NC}"
elif [ "$WARN" -gt 0 ]; then
  echo -e "${CYAN}║${NC}  ${YELLOW}REVIEW: $WARN warning(s) — see details above${NC}                   ${CYAN}║${NC}"
else
  echo -e "${CYAN}║${NC}  ${GREEN}ALL CHECKS PASSED — deployment is healthy${NC}                     ${CYAN}║${NC}"
fi

echo -e "${CYAN}║${NC}                                                                ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
