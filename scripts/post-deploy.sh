#!/usr/bin/env bash
#===============================================================================
#  SpyCloud Identity Exposure Intelligence for Sentinel
#  Post-Deployment Configuration Script -- v2.0.0
#
#  Completes everything ARM templates cannot:
#    Phase 1:  Azure authentication & resource discovery
#    Phase 2:  Resolve DCE Logs Ingestion URI
#    Phase 3:  Resolve DCR Immutable ID
#    Phase 4:  RBAC -- Monitoring Metrics Publisher on DCR for Logic Apps
#    Phase 5:  RBAC -- Function App permissions (Key Vault Secrets User)
#    Phase 6:  RBAC -- Deploying user permissions (Website Contributor, KV access)
#    Phase 7:  MDE API permissions (Machine.Isolate, Machine.ReadWrite.All)
#    Phase 8:  Graph API permissions (User.ReadWrite.All, Directory.ReadWrite.All)
#    Phase 9:  Logic App API connection consent grants
#    Phase 10: Admin consent for all managed identities
#    Phase 11: Deployment verification & health check
#
#  Usage:
#    chmod +x scripts/post-deploy.sh
#    ./scripts/post-deploy.sh -g <resource-group> -w <workspace-name>
#
#  Options:
#    -g, --resource-group   Resource group name (required)
#    -w, --workspace        Log Analytics workspace name (required)
#    -s, --subscription     Azure subscription ID (optional)
#    --skip-mde             Skip MDE API permission grants
#    --skip-graph           Skip Graph API permission grants
#    --skip-consent         Skip Logic App API connection consent
#    --dry-run              Show what would be done without making changes
#    -h, --help             Show this help
#===============================================================================
set -euo pipefail

RED='\033[0;31m';GREEN='\033[0;32m';YELLOW='\033[1;33m'
CYAN='\033[0;36m';MAGENTA='\033[0;35m';BOLD='\033[1m';DIM='\033[2m';NC='\033[0m'
START=$(date +%s)
elapsed(){ echo "$(($(date +%s)-START))s"; }
log(){ echo -e "${DIM}[$(elapsed)]${NC} ${CYAN}ℹ${NC}  $1"; }
ok(){ echo -e "${DIM}[$(elapsed)]${NC} ${GREEN}✅${NC} $1"; }
warn(){ echo -e "${DIM}[$(elapsed)]${NC} ${YELLOW}⚠️${NC}  $1"; }
err(){ echo -e "${DIM}[$(elapsed)]${NC} ${RED}❌${NC} $1"; }
step(){ echo -e "\n${MAGENTA}━━━ $1 ━━━${NC}"; }

PASS_COUNT=0; WARN_COUNT=0; FAIL_COUNT=0

RG=""; WS=""; SUB=""; SKIP_MDE=false; SKIP_GRAPH=false; SKIP_CONSENT=false; DRY=false
while [[ $# -gt 0 ]]; do
  case $1 in
    -g|--resource-group)RG="$2";shift 2;;-w|--workspace)WS="$2";shift 2;;
    -s|--subscription)SUB="$2";shift 2;;--skip-mde)SKIP_MDE=true;shift;;
    --skip-graph)SKIP_GRAPH=true;shift;;--skip-consent)SKIP_CONSENT=true;shift;;
    --dry-run)DRY=true;shift;;
    -h|--help)head -15 "$0"|tail -14;exit 0;;*)err "Unknown: $1";exit 1;;
  esac
done
[[ -z "$RG" || -z "$WS" ]] && { err "Required: -g <rg> -w <ws>"; exit 1; }

DCE_NAME="dce-spycloud-${WS}";DCR_NAME="dcr-spycloud-${WS}"
MDE_PB="SpyCloud-MDE-Remediation-${WS}";CA_PB="SpyCloud-CA-Remediation-${WS}"
MDE_APP="fc780465-2017-40d4-a0c5-307022471b92";GRAPH_APP="00000003-0000-0000-c000-000000000000"
MON_ROLE="3913510d-42f4-4e42-8a64-420c390055eb"
KV_SECRETS_USER_ROLE="4633458b-17de-408a-b874-0445c86b69e6"
WEBSITE_CONTRIBUTOR_ROLE="de139f84-1756-47ae-9be6-808fbbe84772"

echo ""
echo "================================================================"
echo "  SpyCloud Identity Exposure Intelligence for Sentinel"
echo "  Post-Deployment Configuration -- v2.0.0"
echo "================================================================"
echo -e "  Resource Group: ${BOLD}${RG}${NC}"
echo -e "  Workspace:      ${BOLD}${WS}${NC}"
echo -e "  Dry Run:        ${DRY}"

# Phase 1: Auth & Discovery
step "Phase 1/11: Authentication & Resource Discovery"
az account show &>/dev/null || { warn "Logging in..."; az login; }
[[ -n "$SUB" ]] && az account set -s "$SUB"
TENANT=$(az account show --query tenantId -o tsv)
SUBID=$(az account show --query id -o tsv)
CURRENT_USER_OID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null||echo "")
ok "Sub: $(az account show --query name -o tsv) | Tenant: ${TENANT}"
[[ -n "$CURRENT_USER_OID" ]] && log "Current user OID: ${CURRENT_USER_OID}"

# Discover Function App
FN_NAME=""
FN_LIST=$(az functionapp list -g "$RG" --query "[?contains(name,'spycloud')].name" -o tsv 2>/dev/null||echo "")
if [[ -n "$FN_LIST" ]]; then
  FN_NAME=$(echo "$FN_LIST" | head -1)
  log "Discovered Function App: ${FN_NAME}"
else
  warn "No SpyCloud Function App found in ${RG}"
fi

# Discover Key Vault
KV_NAME=""
KV_LIST=$(az keyvault list -g "$RG" --query "[?contains(name,'sc-kv') || contains(name,'spycloud')].name" -o tsv 2>/dev/null||echo "")
if [[ -n "$KV_LIST" ]]; then
  KV_NAME=$(echo "$KV_LIST" | head -1)
  log "Discovered Key Vault: ${KV_NAME}"
else
  warn "No SpyCloud Key Vault found in ${RG}"
fi

# Phase 2: DCE
step "Phase 2/11: Resolve DCE Logs Ingestion URI"
DCE_URI=""
for i in 1 2 3; do
  DCE_URI=$(az monitor data-collection endpoint show --name "$DCE_NAME" -g "$RG" --query "logsIngestion.endpoint" -o tsv 2>/dev/null||echo "")
  [[ -n "$DCE_URI" ]] && { ok "DCE: $DCE_URI"; break; }
  [[ $i -lt 3 ]] && { warn "Attempt $i/3 — waiting 30s..."; sleep 30; }
done
[[ -z "$DCE_URI" ]] && err "DCE not found"

# Phase 3: DCR
step "Phase 3/11: Resolve DCR Immutable ID"
DCR_ID="";DCR_RID=""
for i in 1 2 3; do
  DCR_ID=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" --query "immutableId" -o tsv 2>/dev/null||echo "")
  [[ -n "$DCR_ID" ]] && { DCR_RID=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" --query id -o tsv); ok "DCR: $DCR_ID"; break; }
  [[ $i -lt 3 ]] && { warn "Attempt $i/3 — waiting 45s..."; sleep 45; }
done
[[ -z "$DCR_ID" ]] && err "DCR not found — content template may still be deploying"

# Phase 4: RBAC -- Logic Apps
step "Phase 4/11: RBAC -- Monitoring Metrics Publisher on DCR"
MDE_PID="";CA_PID=""
for PB in "$MDE_PB" "$CA_PB"; do
  PID=$(az logic workflow show --name "$PB" -g "$RG" --query "identity.principalId" -o tsv 2>/dev/null||echo "")
  [[ "$PB" == "$MDE_PB" ]] && MDE_PID="$PID" || CA_PID="$PID"
  if [[ -n "$PID" && -n "$DCR_RID" ]]; then
    $DRY && { log "[DRY] Would assign MonMetricsPub to $PB"; continue; }
    az role assignment create --assignee-object-id "$PID" --assignee-principal-type ServicePrincipal \
      --role "$MON_ROLE" --scope "$DCR_RID" 2>/dev/null && ok "RBAC: $PB" || warn "May exist: $PB"
  else
    warn "Skip: $PB (not found or no DCR)"
  fi
done

# Phase 5: RBAC -- Function App permissions
step "Phase 5/11: RBAC -- Function App Permissions"
FN_PID=""
if [[ -n "$FN_NAME" ]]; then
  FN_PID=$(az functionapp show --name "$FN_NAME" -g "$RG" --query "identity.principalId" -o tsv 2>/dev/null||echo "")
  if [[ -n "$FN_PID" ]]; then
    log "Function App managed identity: ${FN_PID}"
    if [[ -n "$KV_NAME" ]]; then
      KV_RID=$(az keyvault show --name "$KV_NAME" -g "$RG" --query id -o tsv 2>/dev/null||echo "")
      if [[ -n "$KV_RID" ]]; then
        $DRY && { log "[DRY] Would assign Key Vault Secrets User to Function App"; } || {
          az role assignment create --assignee-object-id "$FN_PID" --assignee-principal-type ServicePrincipal \
            --role "$KV_SECRETS_USER_ROLE" --scope "$KV_RID" 2>/dev/null \
            && ok "RBAC Key Vault Secrets User: ${FN_NAME} -> ${KV_NAME}" \
            || warn "May already exist: Key Vault Secrets User for ${FN_NAME}"
        }
      fi
    fi
    if [[ -n "$DCR_RID" ]]; then
      $DRY && { log "[DRY] Would assign MonMetricsPub to Function App"; } || {
        az role assignment create --assignee-object-id "$FN_PID" --assignee-principal-type ServicePrincipal \
          --role "$MON_ROLE" --scope "$DCR_RID" 2>/dev/null \
          && ok "RBAC MonMetricsPub: ${FN_NAME}" \
          || log "Already assigned: MonMetricsPub for ${FN_NAME}"
      }
    fi
  else
    warn "Function App ${FN_NAME} has no managed identity -- enable SystemAssigned identity"
  fi
else
  warn "Skipping Function App RBAC -- no Function App found"
fi

# Phase 6: RBAC -- Deploying user permissions
step "Phase 6/11: RBAC -- Deploying User Permissions"
if [[ -n "$CURRENT_USER_OID" ]]; then
  if [[ -n "$FN_NAME" ]]; then
    FN_RID=$(az functionapp show --name "$FN_NAME" -g "$RG" --query id -o tsv 2>/dev/null||echo "")
    if [[ -n "$FN_RID" ]]; then
      $DRY && { log "[DRY] Would assign Website Contributor to current user"; } || {
        az role assignment create --assignee-object-id "$CURRENT_USER_OID" --assignee-principal-type User \
          --role "$WEBSITE_CONTRIBUTOR_ROLE" --scope "$FN_RID" 2>/dev/null \
          && ok "RBAC Website Contributor: current user -> ${FN_NAME}" \
          || warn "May already exist: Website Contributor for current user"
      }
    fi
  fi
  if [[ -n "$KV_NAME" ]]; then
    KV_RID=$(az keyvault show --name "$KV_NAME" -g "$RG" --query id -o tsv 2>/dev/null||echo "")
    if [[ -n "$KV_RID" ]]; then
      $DRY && { log "[DRY] Would assign Key Vault Secrets User to current user"; } || {
        az role assignment create --assignee-object-id "$CURRENT_USER_OID" --assignee-principal-type User \
          --role "$KV_SECRETS_USER_ROLE" --scope "$KV_RID" 2>/dev/null \
          && ok "RBAC Key Vault Secrets User: current user -> ${KV_NAME}" \
          || warn "May already exist: Key Vault Secrets User for current user"
      }
    fi
  fi
else
  warn "Could not determine current user OID -- skipping user RBAC grants"
  log "Manually grant yourself 'Website Contributor' on the Function App to view host keys"
  log "Manually grant yourself 'Key Vault Secrets User' on the Key Vault to view secrets"
fi

# Phase 7: MDE API
step "Phase 7/11: MDE API Permissions"
if $SKIP_MDE; then warn "Skipped (--skip-mde)"; else
  if [[ -n "$MDE_PID" ]]; then
    MDE_SP=$(az ad sp show --id "$MDE_APP" --query id -o tsv 2>/dev/null||echo "")
    if [[ -n "$MDE_SP" ]]; then
      for RN in "Machine.Isolate" "Machine.ReadWrite.All"; do
        RID=$(az ad sp show --id "$MDE_APP" --query "appRoles[?value=='${RN}'].id" -o tsv 2>/dev/null||echo "")
        [[ -z "$RID" ]] && { warn "${RN} role not found"; continue; }
        $DRY && { log "[DRY] Would assign ${RN}"; continue; }
        az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${MDE_SP}/appRoleAssignedTo" \
          --body "{\"principalId\":\"${MDE_PID}\",\"resourceId\":\"${MDE_SP}\",\"appRoleId\":\"${RID}\"}" \
          2>/dev/null && ok "${RN} → MDE Playbook" || warn "${RN}: may exist or needs admin consent"
      done
    else warn "MDE SP not found — Defender may not be enabled"; fi
  else warn "MDE playbook not found"; fi
fi

# Phase 8: Graph API
step "Phase 8/11: Graph API Permissions"
if $SKIP_GRAPH; then warn "Skipped (--skip-graph)"; else
  if [[ -n "$CA_PID" ]]; then
    GRAPH_SP=$(az ad sp show --id "$GRAPH_APP" --query id -o tsv 2>/dev/null||echo "")
    if [[ -n "$GRAPH_SP" ]]; then
      for RN in "User.ReadWrite.All" "Directory.ReadWrite.All" "GroupMember.ReadWrite.All"; do
        RID=$(az ad sp show --id "$GRAPH_APP" --query "appRoles[?value=='${RN}'].id" -o tsv 2>/dev/null||echo "")
        [[ -z "$RID" ]] && continue
        $DRY && { log "[DRY] Would assign ${RN}"; continue; }
        az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${GRAPH_SP}/appRoleAssignedTo" \
          --body "{\"principalId\":\"${CA_PID}\",\"resourceId\":\"${GRAPH_SP}\",\"appRoleId\":\"${RID}\"}" \
          2>/dev/null && ok "${RN} → CA Playbook" || warn "${RN}: may exist or needs admin consent"
      done
    fi
  else warn "CA playbook not found"; fi
  echo ""
  log "If permissions show 'Pending', grant admin consent:"
  echo -e "  ${CYAN}Portal → Enterprise Applications → find Logic App identity → Permissions → Grant admin consent${NC}"
  echo -e "  ${CYAN}https://portal.azure.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview${NC}"
fi

# Phase 9: Logic App API Connection Consent
step "Phase 9/11: Logic App API Connection Consent"
if $SKIP_CONSENT; then warn "Skipped (--skip-consent)"; else
  CONNECTIONS=$(az resource list -g "$RG" --resource-type "Microsoft.Web/connections" --query "[].name" -o tsv 2>/dev/null||echo "")
  if [[ -n "$CONNECTIONS" ]]; then
    while IFS= read -r CONN_NAME; do
      [[ -z "$CONN_NAME" ]] && continue
      STATUS=$(az resource show -g "$RG" --resource-type "Microsoft.Web/connections" --name "$CONN_NAME" \
        --query "properties.statuses[0].status" -o tsv 2>/dev/null||echo "Unknown")
      if [[ "$STATUS" == "Connected" ]]; then
        ok "API connection '${CONN_NAME}': Connected"
      else
        warn "API connection '${CONN_NAME}': ${STATUS} -- may need manual consent"
      fi
    done <<< "$CONNECTIONS"
  else
    log "No API connections found in ${RG}"
  fi
fi

# Phase 10: Admin Consent
step "Phase 10/11: Admin Consent for Managed Identities"
echo ""
log "To grant admin consent for all managed identities:"
echo -e "  ${CYAN}1. Portal -> Enterprise Applications -> filter by Managed Identity${NC}"
echo -e "  ${CYAN}2. For each SpyCloud identity -> Permissions -> Grant admin consent${NC}"

# Phase 11: Verify
step "Phase 11/11: Deployment Verification & Health Check"
echo ""
echo "================================================================"
echo "  DEPLOYMENT HEALTH CHECK"
echo "================================================================"
echo ""
echo "  Infrastructure:"
az monitor log-analytics workspace show --workspace-name "${WS}" -g "${RG}" &>/dev/null \
  && echo -e "  ${GREEN}PASS${NC}  Workspace: ${WS}" \
  || echo -e "  ${RED}FAIL${NC}  Workspace: ${WS}"
[[ -n "$DCE_URI" ]] && echo -e "  ${GREEN}PASS${NC}  DCE: ${DCE_NAME}" || echo -e "  ${RED}FAIL${NC}  DCE: ${DCE_NAME}"
[[ -n "$DCR_ID" ]]  && echo -e "  ${GREEN}PASS${NC}  DCR: ${DCR_NAME}" || echo -e "  ${RED}FAIL${NC}  DCR: ${DCR_NAME}"
if [[ -n "$FN_NAME" ]]; then
  az functionapp show --name "${FN_NAME}" -g "${RG}" &>/dev/null \
    && echo -e "  ${GREEN}PASS${NC}  Function App: ${FN_NAME}" \
    || echo -e "  ${RED}FAIL${NC}  Function App: ${FN_NAME}"
fi
if [[ -n "$KV_NAME" ]]; then
  az keyvault show --name "${KV_NAME}" -g "${RG}" &>/dev/null \
    && echo -e "  ${GREEN}PASS${NC}  Key Vault: ${KV_NAME}" \
    || echo -e "  ${RED}FAIL${NC}  Key Vault: ${KV_NAME}"
fi

echo ""
echo "  Custom Log Tables:"
for TABLE in SpyCloud_BreachWatch_CL SpyCloud_BreachCatalog_CL SpyCloud_Compass_CL SpyCloud_SessionIP_CL SpyCloud_Investigations_CL SpyCloud_IDLink_CL SpyCloud_Exposure_CL SpyCloud_CAP_CL SpyCloud_DataPartnership_CL; do
  EXISTS=$(az monitor log-analytics workspace table show --workspace-name "$WS" -g "$RG" --name "$TABLE" --query "name" -o tsv 2>/dev/null||echo "")
  if [[ -n "$EXISTS" ]]; then
    echo -e "  ${GREEN}PASS${NC}  ${TABLE}"
  else
    echo -e "  ${YELLOW}WARN${NC}  ${TABLE}: not yet created (created on first data ingestion)"
  fi
done

echo ""
echo "================================================================"
echo "  NEXT STEPS:"
echo "  1. Verify SpyCloud API key is set in Key Vault"
echo "  2. Enable desired analytics rules in Sentinel"
echo "  3. Upload copilot/SpyCloud_Plugin.yaml to Copilot Sources"
echo "  4. Upload copilot/SpyCloud_Agent.yaml to Copilot Build"
echo "  5. Configure Entra ID diagnostic settings for sign-in logs"
echo "  6. Install IdP connectors (Okta/Duo/Ping) if applicable"
echo "================================================================"
echo ""
