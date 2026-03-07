#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#  SpyCloud Sentinel — Interactive Guided Deployment
#  Version: 4.0.0
#
#  One command. Full automation. Interactive menus. Detailed logging.
#  Works in: Azure Cloud Shell, Linux, macOS, WSL, GitHub Actions
#  Requires: Azure CLI (az) — ZERO POWERSHELL
#
#  Quick start:
#    curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-all.sh | bash
#
#  With arguments (non-interactive):
#    ./scripts/deploy-all.sh -g myRG -w myWS -k MY-API-KEY --location eastus
#═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m';GREEN='\033[0;32m';YELLOW='\033[1;33m';BLUE='\033[0;34m'
CYAN='\033[0;36m';MAGENTA='\033[0;35m';BOLD='\033[1m';DIM='\033[2m';NC='\033[0m'
TEAL='\033[38;2;0;180;216m';NAVY='\033[38;2;13;27;42m';CORAL='\033[38;2;224;122;95m'

T0=$(date +%s)
elapsed(){ printf "%dm%02ds" $(( ($(date +%s)-T0)/60 )) $(( ($(date +%s)-T0)%60 )); }

# ─── Logging ──────────────────────────────────────────────────────────────────
LOGFILE="/tmp/spycloud-deploy-$(date +%Y%m%d-%H%M%S).log"

_log(){
    local level="$1" msg="$2" color="$3"
    local ts="[$(elapsed)]"
    echo -e "${DIM}${ts}${NC} ${color}[${level}]${NC} ${msg}"
    echo "[$(date -Iseconds)] [${level}] ${msg}" >> "$LOGFILE"
}
log()  { _log "INFO" "$1" "$CYAN"; }
ok()   { _log " OK " "$1" "$GREEN"; }
warn() { _log "WARN" "$1" "$YELLOW"; }
err()  { _log "FAIL" "$1" "$RED"; }
step() { echo -e "\n${TEAL}╔══════════════════════════════════════════════╗${NC}"; echo -e "${TEAL}║${NC} ${BOLD}$1${NC}"; echo -e "${TEAL}╚══════════════════════════════════════════════╝${NC}"; echo ""; }
debug(){ echo "[$(date -Iseconds)] [DEBUG] $1" >> "$LOGFILE"; }

# ─── ASCII Banner ─────────────────────────────────────────────────────────────
show_banner() {
cat << 'ASCIIEOF'

   ███████╗██████╗ ██╗   ██╗ ██████╗██╗      ██████╗ ██╗   ██╗██████╗
   ██╔════╝██╔══██╗╚██╗ ██╔╝██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗
   ███████╗██████╔╝ ╚████╔╝ ██║     ██║     ██║   ██║██║   ██║██║  ██║
   ╚════██║██╔═══╝   ╚██╔╝  ██║     ██║     ██║   ██║██║   ██║██║  ██║
   ███████║██║        ██║   ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝
   ╚══════╝╚═╝        ╚═╝    ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝

ASCIIEOF
echo -e "   ${TEAL}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "   ${BOLD}Microsoft Sentinel — Unified Threat Intelligence Platform${NC}"
echo -e "   ${DIM}Automated deployment with full post-config • v4.0.0${NC}"
echo -e "   ${TEAL}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "   ${DIM}Log file: ${LOGFILE}${NC}"
echo ""
}

# ─── Parse Arguments ──────────────────────────────────────────────────────────
RG="";WS="";KEY="";LOC=""
ENABLE_MDE=true;ENABLE_CA=true;ENABLE_KV=true
ENABLE_RULES=false;ENABLE_NOTIFY=false;EMAIL=""
INTERACTIVE=true;TEMPLATE_URL=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -g|--resource-group)RG="$2";shift 2;;
    -w|--workspace)WS="$2";shift 2;;
    -k|--api-key)KEY="$2";shift 2;;
    -l|--location)LOC="$2";shift 2;;
    --enable-rules)ENABLE_RULES=true;shift;;
    --enable-notify)ENABLE_NOTIFY=true;shift;;
    --disable-mde)ENABLE_MDE=false;shift;;
    --disable-ca)ENABLE_CA=false;shift;;
    --disable-kv)ENABLE_KV=false;shift;;
    --email)EMAIL="$2";shift 2;;
    --template)TEMPLATE_URL="$2";shift 2;;
    --non-interactive)INTERACTIVE=false;shift;;
    -h|--help)
      show_banner
      echo "  USAGE:"
      echo "    $0 [options]"
      echo ""
      echo "  OPTIONS:"
      echo "    -g, --resource-group   Resource group name"
      echo "    -w, --workspace        Workspace name"
      echo "    -k, --api-key          SpyCloud API key"
      echo "    -l, --location         Azure region (default: guided selection)"
      echo "    --enable-rules         Deploy full analytics rules library"
      echo "    --enable-notify        Enable email/Teams notifications"
      echo "    --disable-mde          Skip MDE playbook"
      echo "    --disable-ca           Skip CA playbook"
      echo "    --disable-kv           Skip Key Vault"
      echo "    --email EMAIL          Notification email address"
      echo "    --template URL         Custom ARM template URL"
      echo "    --non-interactive      Skip all prompts (requires -g -w -k)"
      echo "    -h, --help             Show this help"
      echo ""
      echo "  EXAMPLES:"
      echo "    # Fully interactive (Cloud Shell):"
      echo "    ./scripts/deploy-all.sh"
      echo ""
      echo "    # Non-interactive with all options:"
      echo "    ./scripts/deploy-all.sh -g spycloud-rg -w spycloud-ws -k YOUR-KEY -l eastus"
      echo ""
      echo "    # Curl one-liner:"
      echo "    curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-all.sh | bash"
      exit 0;;
    *)err "Unknown option: $1";exit 1;;
  esac
done

# If key args provided, skip interactive
[[ -n "$RG" && -n "$WS" && -n "$KEY" ]] && INTERACTIVE=false

# ─── Detect template URL ─────────────────────────────────────────────────────
if [[ -z "$TEMPLATE_URL" ]]; then
    if [[ -f "azuredeploy.json" ]]; then
        TEMPLATE_URL="azuredeploy.json"
        debug "Using local template: azuredeploy.json"
    elif [[ -f "../azuredeploy.json" ]]; then
        TEMPLATE_URL="../azuredeploy.json"
        debug "Using local template: ../azuredeploy.json"
    else
        TEMPLATE_URL="https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json"
        debug "Using remote template from GitHub"
    fi
fi

# Constants
MDE_APP="fc780465-2017-40d4-a0c5-307022471b92"
GRAPH_APP="00000003-0000-0000-c000-000000000000"
MON_ROLE="3913510d-42f4-4e42-8a64-420c390055eb"

# ═══════════════════════════════════════════════════════════════════════════════
show_banner

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Authentication
# ═══════════════════════════════════════════════════════════════════════════════
step "Phase 1 of 9 — Azure Authentication"

if az account show &>/dev/null; then
    ACCT_NAME=$(az account show --query name -o tsv)
    TENANT=$(az account show --query tenantId -o tsv)
    SUBID=$(az account show --query id -o tsv)
    ok "Already authenticated"
    ok "Subscription: ${BOLD}${ACCT_NAME}${NC}"
    ok "Tenant: ${TENANT}"
    debug "Sub=$SUBID Tenant=$TENANT"
else
    warn "Not logged in to Azure"
    log "Opening browser for authentication..."
    az login --use-device-code 2>/dev/null || az login
    ACCT_NAME=$(az account show --query name -o tsv)
    TENANT=$(az account show --query tenantId -o tsv)
    SUBID=$(az account show --query id -o tsv)
    ok "Authenticated: ${ACCT_NAME}"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Interactive Configuration Menu
# ═══════════════════════════════════════════════════════════════════════════════
if $INTERACTIVE; then
step "Phase 2 of 9 — Deployment Configuration"

echo -e "${TEAL}┌──────────────────────────────────────────────┐${NC}"
echo -e "${TEAL}│${NC}  ${BOLD}SpyCloud Sentinel Setup Wizard${NC}               ${TEAL}│${NC}"
echo -e "${TEAL}│${NC}  Answer the following to configure deployment ${TEAL}│${NC}"
echo -e "${TEAL}└──────────────────────────────────────────────┘${NC}"
echo ""

# Resource Group
if [[ -z "$RG" ]]; then
    echo -e "${BOLD}1. Resource Group${NC}"
    echo -e "   ${DIM}All resources will be deployed here.${NC}"
    echo -e "   ${DIM}A new group will be created if it doesn't exist.${NC}"
    echo ""
    read -rp "   Enter resource group name [spycloud-sentinel]: " RG
    RG="${RG:-spycloud-sentinel}"
    echo ""
fi

# Workspace
if [[ -z "$WS" ]]; then
    echo -e "${BOLD}2. Log Analytics Workspace${NC}"
    echo -e "   ${DIM}Microsoft Sentinel will be enabled on this workspace.${NC}"
    echo -e "   ${DIM}A new workspace will be created if it doesn't exist.${NC}"
    echo ""
    read -rp "   Enter workspace name [spycloud-ws]: " WS
    WS="${WS:-spycloud-ws}"
    echo ""
fi

# API Key
if [[ -z "$KEY" ]]; then
    echo -e "${BOLD}3. SpyCloud API Key${NC}"
    echo -e "   ${DIM}Get from: portal.spycloud.com → Settings → API Keys${NC}"
    echo ""
    read -rsp "   Enter API key (hidden): " KEY
    echo ""
    [[ -z "$KEY" ]] && { err "API key is required"; exit 1; }
    echo ""
fi

# Region
if [[ -z "$LOC" ]]; then
    echo -e "${BOLD}4. Azure Region${NC}"
    echo -e "   ${DIM}Select a region for deployment:${NC}"
    echo ""
    REGIONS=("eastus" "eastus2" "westus2" "centralus" "northeurope" "westeurope" "uksouth" "australiaeast")
    for i in "${!REGIONS[@]}"; do
        echo -e "     ${TEAL}[$((i+1))]${NC} ${REGIONS[$i]}"
    done
    echo ""
    read -rp "   Select region [1]: " REGION_CHOICE
    REGION_CHOICE="${REGION_CHOICE:-1}"
    LOC="${REGIONS[$((REGION_CHOICE-1))]}"
    echo ""
fi

# Feature toggles
echo -e "${BOLD}5. Feature Configuration${NC}"
echo ""

read -rp "   Enable MDE device isolation playbook? [Y/n]: " ans
[[ "$ans" =~ ^[Nn] ]] && ENABLE_MDE=false

read -rp "   Enable CA identity protection playbook? [Y/n]: " ans
[[ "$ans" =~ ^[Nn] ]] && ENABLE_CA=false

read -rp "   Enable Azure Key Vault for API key? [Y/n]: " ans
[[ "$ans" =~ ^[Nn] ]] && ENABLE_KV=false

read -rp "   Deploy full analytics rules library (17 rules, all disabled)? [y/N]: " ans
[[ "$ans" =~ ^[Yy] ]] && ENABLE_RULES=true

read -rp "   Enable email/Teams notifications? [y/N]: " ans
if [[ "$ans" =~ ^[Yy] ]]; then
    ENABLE_NOTIFY=true
    read -rp "   Notification email address: " EMAIL
fi
echo ""

# Confirmation
echo -e "${TEAL}┌──────────────────────────────────────────────┐${NC}"
echo -e "${TEAL}│${NC}  ${BOLD}Deployment Summary${NC}                          ${TEAL}│${NC}"
echo -e "${TEAL}├──────────────────────────────────────────────┤${NC}"
echo -e "${TEAL}│${NC}  Resource Group:    ${BOLD}${RG}${NC}"
echo -e "${TEAL}│${NC}  Workspace:         ${BOLD}${WS}${NC}"
echo -e "${TEAL}│${NC}  Region:            ${BOLD}${LOC}${NC}"
echo -e "${TEAL}│${NC}  API Key:           ${BOLD}${KEY:0:8}...${NC}"
echo -e "${TEAL}│${NC}  MDE Playbook:      ${BOLD}${ENABLE_MDE}${NC}"
echo -e "${TEAL}│${NC}  CA Playbook:       ${BOLD}${ENABLE_CA}${NC}"
echo -e "${TEAL}│${NC}  Key Vault:         ${BOLD}${ENABLE_KV}${NC}"
echo -e "${TEAL}│${NC}  Rules Library:     ${BOLD}${ENABLE_RULES}${NC}"
echo -e "${TEAL}│${NC}  Notifications:     ${BOLD}${ENABLE_NOTIFY}${NC}"
echo -e "${TEAL}└──────────────────────────────────────────────┘${NC}"
echo ""
read -rp "   Proceed with deployment? [Y/n]: " confirm
[[ "$confirm" =~ ^[Nn] ]] && { log "Deployment cancelled."; exit 0; }

else
    # Non-interactive defaults
    LOC="${LOC:-eastus}"
    step "Phase 2 of 9 — Configuration (non-interactive)"
    ok "RG=${RG} WS=${WS} LOC=${LOC}"
fi

debug "Config: RG=$RG WS=$WS LOC=$LOC MDE=$ENABLE_MDE CA=$ENABLE_CA KV=$ENABLE_KV RULES=$ENABLE_RULES"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: Resource Group
# ═══════════════════════════════════════════════════════════════════════════════
step "Phase 3 of 9 — Resource Group"

if az group show --name "$RG" &>/dev/null; then
    ok "Resource group exists: ${RG}"
else
    log "Creating resource group: ${RG} in ${LOC}..."
    az group create --name "$RG" --location "$LOC" \
        --tags solution=SpyCloud-Sentinel version=4.0.0 -o none 2>>"$LOGFILE"
    ok "Created: ${RG}"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: ARM Template Deployment
# ═══════════════════════════════════════════════════════════════════════════════
step "Phase 4 of 9 — ARM Template Deployment"

DEPLOY_NAME="spycloud-$(date +%Y%m%d%H%M%S)"
log "Deployment name: ${DEPLOY_NAME}"
log "Template: ${TEMPLATE_URL}"
log "Deploying... (this typically takes 3-8 minutes)"

DEPLOY_CMD="az deployment group create \
  --name $DEPLOY_NAME \
  --resource-group $RG \
  --parameters \
    workspace=$WS \
    createNewWorkspace=true \
    spycloudApiKey=$KEY \
    deploymentRegion=$LOC \
    resourceGroupName=$RG \
    subscription=$SUBID \
    enableMdePlaybook=$ENABLE_MDE \
    enableCaPlaybook=$ENABLE_CA \
    enableKeyVault=$ENABLE_KV \
    enableAnalyticsRule=true \
    enableAutomationRule=true \
    enableAnalyticsRulesLibrary=$ENABLE_RULES \
    enableNotifications=$ENABLE_NOTIFY"

# Use --template-file for local, --template-uri for remote
if [[ "$TEMPLATE_URL" == http* ]]; then
    DEPLOY_CMD="$DEPLOY_CMD --template-uri $TEMPLATE_URL"
else
    DEPLOY_CMD="$DEPLOY_CMD --template-file $TEMPLATE_URL"
fi

if [[ -n "$EMAIL" ]]; then
    DEPLOY_CMD="$DEPLOY_CMD notificationEmail=$EMAIL"
fi

debug "Deploy command: $DEPLOY_CMD"

# Execute deployment
eval "$DEPLOY_CMD" -o none 2>>"$LOGFILE" && DEPLOY_OK=true || DEPLOY_OK=false

if $DEPLOY_OK; then
    ok "ARM deployment succeeded!"
else
    warn "ARM deployment had issues — checking status..."
    STATE=$(az deployment group show --name "$DEPLOY_NAME" -g "$RG" \
        --query "properties.provisioningState" -o tsv 2>/dev/null || echo "Unknown")
    warn "Deployment state: ${STATE}"
    warn "Check log for details: ${LOGFILE}"
    log "Continuing with post-deployment steps..."
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: Wait for Content Template
# ═══════════════════════════════════════════════════════════════════════════════
step "Phase 5 of 9 — Waiting for Content Template Resources"

log "The Sentinel content template creates the DCR + custom tables."
log "This happens asynchronously after the main deployment."
log "Waiting 75 seconds for resources to finalize..."

for i in $(seq 1 15); do
    printf "\r   ⏳ Waiting... %ds / 75s" "$((i*5))"
    sleep 5
done
echo ""
ok "Wait complete"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: Resolve DCE + DCR
# ═══════════════════════════════════════════════════════════════════════════════
step "Phase 6 of 9 — Resolve DCE URI + DCR Immutable ID"

DCE_NAME="dce-spycloud-${WS}";DCR_NAME="dcr-spycloud-${WS}"
DCE_URI="";DCR_ID="";DCR_RID=""

for attempt in 1 2 3 4 5; do
    debug "DCE/DCR resolve attempt $attempt"
    DCE_URI=$(az monitor data-collection endpoint show --name "$DCE_NAME" -g "$RG" \
        --query "logsIngestion.endpoint" -o tsv 2>/dev/null || echo "")
    DCR_ID=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" \
        --query "immutableId" -o tsv 2>/dev/null || echo "")
    DCR_RID=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" \
        --query "id" -o tsv 2>/dev/null || echo "")
    
    [[ -n "$DCE_URI" && -n "$DCR_ID" ]] && break
    [[ $attempt -lt 5 ]] && { warn "Attempt ${attempt}/5 — resources not ready, waiting 30s..."; sleep 30; }
done

[[ -n "$DCE_URI" ]] && ok "DCE URI: ${DCE_URI}" || err "DCE not resolved"
[[ -n "$DCR_ID" ]]  && ok "DCR ID:  ${DCR_ID}" || err "DCR not resolved"
debug "DCE=$DCE_URI DCR=$DCR_ID DCR_RID=$DCR_RID"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7: RBAC Assignments
# ═══════════════════════════════════════════════════════════════════════════════
step "Phase 7 of 9 — RBAC: Monitoring Metrics Publisher"

MDE_PB="SpyCloud-MDE-Remediation-${WS}";CA_PB="SpyCloud-CA-Remediation-${WS}"
MDE_PID="";CA_PID=""

for PB in "$MDE_PB" "$CA_PB"; do
    PID=$(az logic workflow show --name "$PB" -g "$RG" \
        --query "identity.principalId" -o tsv 2>/dev/null || echo "")
    [[ "$PB" == "$MDE_PB" ]] && MDE_PID="$PID" || CA_PID="$PID"
    
    if [[ -n "$PID" && -n "$DCR_RID" ]]; then
        debug "Assigning MonMetricsPub: principal=$PID scope=$DCR_RID"
        az role assignment create \
            --assignee-object-id "$PID" \
            --assignee-principal-type ServicePrincipal \
            --role "$MON_ROLE" --scope "$DCR_RID" 2>>"$LOGFILE" \
            && ok "RBAC assigned: ${PB}" \
            || warn "RBAC may already exist: ${PB}"
    else
        warn "Skipping ${PB} — not found or DCR not available"
    fi
done

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8: API Permissions (MDE + Graph)
# ═══════════════════════════════════════════════════════════════════════════════
step "Phase 8 of 9 — API Permissions (MDE + Graph)"

assign_app_role() {
    local principal="$1" sp_app_id="$2" role_name="$3" label="$4"
    local sp_id role_id
    
    sp_id=$(az ad sp show --id "$sp_app_id" --query id -o tsv 2>/dev/null || echo "")
    [[ -z "$sp_id" ]] && { warn "${label}: Service principal not found"; return; }
    
    role_id=$(az ad sp show --id "$sp_app_id" \
        --query "appRoles[?value=='${role_name}'].id" -o tsv 2>/dev/null || echo "")
    [[ -z "$role_id" ]] && { warn "${label}: Role '${role_name}' not found"; return; }
    
    debug "Assigning ${role_name}: principal=$principal sp=$sp_id role=$role_id"
    
    az rest --method POST \
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${sp_id}/appRoleAssignedTo" \
        --body "{\"principalId\":\"${principal}\",\"resourceId\":\"${sp_id}\",\"appRoleId\":\"${role_id}\"}" \
        2>>"$LOGFILE" \
        && ok "${role_name} → ${label}" \
        || warn "${role_name} → ${label}: may exist or needs admin consent"
}

# MDE permissions
if [[ -n "$MDE_PID" ]] && $ENABLE_MDE; then
    log "Granting MDE API permissions..."
    assign_app_role "$MDE_PID" "$MDE_APP" "Machine.Isolate" "MDE Playbook"
    assign_app_role "$MDE_PID" "$MDE_APP" "Machine.ReadWrite.All" "MDE Playbook"
else
    warn "MDE playbook not available — skipping MDE permissions"
fi

# Graph permissions
if [[ -n "$CA_PID" ]] && $ENABLE_CA; then
    log "Granting Microsoft Graph API permissions..."
    assign_app_role "$CA_PID" "$GRAPH_APP" "User.ReadWrite.All" "CA Playbook"
    assign_app_role "$CA_PID" "$GRAPH_APP" "Directory.ReadWrite.All" "CA Playbook"
    assign_app_role "$CA_PID" "$GRAPH_APP" "GroupMember.ReadWrite.All" "CA Playbook"
else
    warn "CA playbook not available — skipping Graph permissions"
fi

echo ""
log "If any permissions show 'Pending', grant admin consent:"
echo -e "  ${TEAL}https://portal.azure.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview${NC}"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 9: Verification
# ═══════════════════════════════════════════════════════════════════════════════
step "Phase 9 of 9 — Deployment Verification"

verify() {
    local name="$1"; shift
    if "$@" &>/dev/null; then
        echo -e "  ${GREEN}✅${NC} ${name}"
    else
        echo -e "  ${YELLOW}⚠️${NC}  ${name}"
    fi
}

echo ""
echo -e "${TEAL}┌──────────────────────────────────────────────────────────┐${NC}"
echo -e "${TEAL}│${NC}  ${BOLD}Resource Status${NC}                                        ${TEAL}│${NC}"
echo -e "${TEAL}├──────────────────────────────────────────────────────────┤${NC}"
verify "Log Analytics Workspace" az monitor log-analytics workspace show --workspace-name "$WS" -g "$RG"
[[ -n "$DCE_URI" ]] && echo -e "  ${GREEN}✅${NC} Data Collection Endpoint" || echo -e "  ${RED}❌${NC} Data Collection Endpoint"
[[ -n "$DCR_ID" ]]  && echo -e "  ${GREEN}✅${NC} Data Collection Rule" || echo -e "  ${YELLOW}⚠️${NC}  Data Collection Rule (may still be deploying)"
verify "Key Vault" az keyvault list -g "$RG" --query "[0].name"
verify "MDE Logic App ($MDE_PB)" az logic workflow show --name "$MDE_PB" -g "$RG"
verify "CA Logic App ($CA_PB)" az logic workflow show --name "$CA_PB" -g "$RG"
echo -e "${TEAL}└──────────────────────────────────────────────────────────┘${NC}"

# ═══════════════════════════════════════════════════════════════════════════════
# Final Summary
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
cat << 'SUMMARYEOF'

   ███████╗██████╗ ██╗   ██╗ ██████╗██╗      ██████╗ ██╗   ██╗██████╗
   ██╔════╝██╔══██╗╚██╗ ██╔╝██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗
   ███████╗██████╔╝ ╚████╔╝ ██║     ██║     ██║   ██║██║   ██║██║  ██║
   ╚════██║██╔═══╝   ╚██╔╝  ██║     ██║     ██║   ██║██║   ██║██║  ██║
   ███████║██║        ██║   ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝
   ╚══════╝╚═╝        ╚═╝    ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝

SUMMARYEOF

echo -e "${TEAL}═══════════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}${BOLD}DEPLOYMENT COMPLETE${NC}  •  $(elapsed)"
echo -e "${TEAL}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Resource Group:${NC}    $RG"
echo -e "  ${BOLD}Workspace:${NC}         $WS"
echo -e "  ${BOLD}Region:${NC}            $LOC"
[[ -n "$DCE_URI" ]] && echo -e "  ${BOLD}DCE URI:${NC}           $DCE_URI"
[[ -n "$DCR_ID" ]]  && echo -e "  ${BOLD}DCR Immutable ID:${NC}  $DCR_ID"
echo -e "  ${BOLD}Log File:${NC}          $LOGFILE"
echo ""
echo -e "${TEAL}───────────────────────────────────────────────────────────────${NC}"
echo -e "  ${BOLD}Remaining Steps:${NC}"
echo ""
echo -e "  ${CORAL}1.${NC} Verify data flow:"
echo -e "     Sentinel → Data connectors → filter 'SpyCloud'"
echo ""
echo -e "  ${CORAL}2.${NC} Review & enable analytics rules:"
echo -e "     Sentinel → Analytics → filter 'SpyCloud' → enable desired rules"
echo ""
echo -e "  ${CORAL}3.${NC} Upload Security Copilot files:"
echo -e "     Plugin: copilot/SpyCloud_Plugin.yaml → Sources → Custom"
echo -e "     Agent:  copilot/SpyCloud_Agent.yaml  → Build → Upload YAML"
echo ""
echo -e "  ${CORAL}4.${NC} Configure Entra ID diagnostic settings (manual):"
echo -e "     Entra ID → Monitoring → Diagnostic settings → Add"
echo -e "     Check: SignInLogs, AuditLogs, RiskyUsers → Send to ${WS}"
echo ""
echo -e "  ${CORAL}5.${NC} Install IdP connectors (optional):"
echo -e "     Sentinel → Content Hub → Okta / Duo / Ping / CyberArk"
echo ""
echo -e "  ${CORAL}6.${NC} Grant admin consent (if permissions show 'Pending'):"
echo -e "     ${CYAN}https://portal.azure.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview${NC}"
echo ""
echo -e "${TEAL}═══════════════════════════════════════════════════════════════${NC}"
echo ""
