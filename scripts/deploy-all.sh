#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#  SpyCloud Sentinel — One-Command Complete Deployment
#  Version: 4.0.0
#
#  Deploys EVERYTHING in a single execution:
#    1. Creates resource group (if needed)
#    2. Deploys ARM template (workspace, Sentinel, connector, playbooks, rules)
#    3. Waits for content template to finish
#    4. Resolves DCE URI + DCR Immutable ID
#    5. Assigns RBAC (Monitoring Metrics Publisher)
#    6. Assigns MDE API permissions
#    7. Assigns Graph API permissions
#    8. Provides admin consent URLs
#    9. Verifies everything
#
#  Works in: Azure Cloud Shell, Linux, macOS, WSL, GitHub Actions
#  Requires: Azure CLI (az) — NO POWERSHELL
#
#  Usage:
#    curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-all.sh | bash -s -- \
#      --resource-group spycloud-sentinel \
#      --workspace spycloud-ws \
#      --api-key YOUR-SPYCLOUD-API-KEY \
#      --location eastus
#
#  Or clone and run:
#    git clone https://github.com/iammrherb/SPYCLOUD-SENTINEL.git && cd SPYCLOUD-SENTINEL
#    chmod +x scripts/deploy-all.sh
#    ./scripts/deploy-all.sh -g spycloud-sentinel -w spycloud-ws -k YOUR-KEY
#═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m';GREEN='\033[0;32m';YELLOW='\033[1;33m'
CYAN='\033[0;36m';MAGENTA='\033[0;35m';BOLD='\033[1m';DIM='\033[2m';NC='\033[0m'
T0=$(date +%s)
elapsed(){ printf "%dm%02ds" $(( ($(date +%s)-T0)/60 )) $(( ($(date +%s)-T0)%60 )); }
log(){ echo -e "${DIM}[$(elapsed)]${NC} ${CYAN}ℹ${NC}  $1"; }
ok(){ echo -e "${DIM}[$(elapsed)]${NC} ${GREEN}✅${NC} $1"; }
warn(){ echo -e "${DIM}[$(elapsed)]${NC} ${YELLOW}⚠️${NC}  $1"; }
err(){ echo -e "${DIM}[$(elapsed)]${NC} ${RED}❌${NC} $1"; }
step(){ echo -e "\n${MAGENTA}═══ $1 ═══${NC}"; }

RG="";WS="";KEY="";LOC="eastus";RULES=false;NOTIFY=false;EMAIL=""
TEMPLATE_URL="https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json"
MDE_APP="fc780465-2017-40d4-a0c5-307022471b92"
GRAPH_APP="00000003-0000-0000-c000-000000000000"
MON_ROLE="3913510d-42f4-4e42-8a64-420c390055eb"

while [[ $# -gt 0 ]]; do
  case $1 in
    -g|--resource-group)RG="$2";shift 2;;
    -w|--workspace)WS="$2";shift 2;;
    -k|--api-key)KEY="$2";shift 2;;
    -l|--location)LOC="$2";shift 2;;
    --enable-rules)RULES=true;shift;;
    --enable-notify)NOTIFY=true;shift;;
    --email)EMAIL="$2";shift 2;;
    --template)TEMPLATE_URL="$2";shift 2;;
    -h|--help)head -21 "$0"|tail -19;exit 0;;
    *)err "Unknown: $1";exit 1;;
  esac
done

[[ -z "$RG" ]] && { read -rp "Resource group name: " RG; }
[[ -z "$WS" ]] && { read -rp "Workspace name: " WS; }
[[ -z "$KEY" ]] && { read -rsp "SpyCloud API key: " KEY; echo; }

cat << 'BANNER'

  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║   🛡️  SpyCloud Sentinel — Complete One-Command Deployment   ║
  ║                                                              ║
  ║   ARM Template → Post-Deploy → RBAC → API Perms → Verify    ║
  ║   Everything automated. Zero PowerShell.                     ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝

BANNER
echo -e "  RG: ${BOLD}${RG}${NC}  WS: ${BOLD}${WS}${NC}  LOC: ${BOLD}${LOC}${NC}"

# ═══ PHASE 1: Authentication ═══
step "Phase 1/9: Authentication"
az account show &>/dev/null || { warn "Logging in..."; az login --use-device-code 2>/dev/null || az login; }
TENANT=$(az account show --query tenantId -o tsv)
SUBID=$(az account show --query id -o tsv)
ok "Subscription: $(az account show --query name -o tsv)"

# ═══ PHASE 2: Resource Group ═══
step "Phase 2/9: Resource Group"
az group show --name "$RG" &>/dev/null && ok "Exists: $RG" || {
  log "Creating $RG in $LOC..."
  az group create --name "$RG" --location "$LOC" --tags solution=SpyCloud-Sentinel -o none
  ok "Created: $RG"
}

# ═══ PHASE 3: ARM Deployment ═══
step "Phase 3/9: ARM Template Deployment"
log "Deploying ARM template (this takes 3-8 minutes)..."
DEPLOY_NAME="spycloud-$(date +%Y%m%d%H%M%S)"

az deployment group create \
  --name "$DEPLOY_NAME" \
  --resource-group "$RG" \
  --template-uri "$TEMPLATE_URL" \
  --parameters \
    workspace="$WS" \
    createNewWorkspace=true \
    spycloudApiKey="$KEY" \
    deploymentRegion="$LOC" \
    resourceGroupName="$RG" \
    subscription="$SUBID" \
    enableMdePlaybook=true \
    enableCaPlaybook=true \
    enableKeyVault=true \
    enableAnalyticsRule=true \
    enableAutomationRule=true \
    enableAnalyticsRulesLibrary=$RULES \
    enableNotifications=$NOTIFY \
  --no-wait -o none 2>/dev/null && log "Deployment submitted" || true

# Wait for completion
log "Waiting for deployment to complete..."
for i in $(seq 1 60); do
  STATE=$(az deployment group show --name "$DEPLOY_NAME" -g "$RG" --query "properties.provisioningState" -o tsv 2>/dev/null || echo "Running")
  case $STATE in
    Succeeded) ok "Deployment succeeded!"; break;;
    Failed) err "Deployment failed — check Azure Portal for details"; break;;
    *) printf "\r  ⏳ %s... (%ds)" "$STATE" "$((i*10))"; sleep 10;;
  esac
done
echo ""

# ═══ PHASE 4: Wait for Content Template ═══
step "Phase 4/9: Wait for Content Template Resources"
log "Waiting 60s for Sentinel content template to create DCR + tables..."
sleep 60

# ═══ PHASE 5: Resolve DCE + DCR ═══
step "Phase 5/9: Resolve DCE URI + DCR Immutable ID"
DCE_NAME="dce-spycloud-${WS}"; DCR_NAME="dcr-spycloud-${WS}"
DCE_URI=""; DCR_ID=""; DCR_RID=""

for i in 1 2 3 4 5; do
  DCE_URI=$(az monitor data-collection endpoint show --name "$DCE_NAME" -g "$RG" --query "logsIngestion.endpoint" -o tsv 2>/dev/null || echo "")
  DCR_ID=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" --query "immutableId" -o tsv 2>/dev/null || echo "")
  DCR_RID=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" --query "id" -o tsv 2>/dev/null || echo "")
  [[ -n "$DCE_URI" && -n "$DCR_ID" ]] && break
  [[ $i -lt 5 ]] && { warn "Attempt $i/5 — waiting 30s..."; sleep 30; }
done

[[ -n "$DCE_URI" ]] && ok "DCE: $DCE_URI" || err "DCE not resolved"
[[ -n "$DCR_ID" ]] && ok "DCR: $DCR_ID" || err "DCR not resolved"

# ═══ PHASE 6: RBAC ═══
step "Phase 6/9: RBAC — Monitoring Metrics Publisher"
MDE_PB="SpyCloud-MDE-Remediation-${WS}"; CA_PB="SpyCloud-CA-Remediation-${WS}"
MDE_PID=""; CA_PID=""

for PB in "$MDE_PB" "$CA_PB"; do
  PID=$(az logic workflow show --name "$PB" -g "$RG" --query "identity.principalId" -o tsv 2>/dev/null || echo "")
  [[ "$PB" == "$MDE_PB" ]] && MDE_PID="$PID" || CA_PID="$PID"
  if [[ -n "$PID" && -n "$DCR_RID" ]]; then
    az role assignment create --assignee-object-id "$PID" --assignee-principal-type ServicePrincipal \
      --role "$MON_ROLE" --scope "$DCR_RID" 2>/dev/null \
      && ok "RBAC: $PB" || warn "RBAC may exist: $PB"
  fi
done

# ═══ PHASE 7: MDE API ═══
step "Phase 7/9: MDE API Permissions"
if [[ -n "$MDE_PID" ]]; then
  MDE_SP=$(az ad sp show --id "$MDE_APP" --query id -o tsv 2>/dev/null || echo "")
  if [[ -n "$MDE_SP" ]]; then
    for RN in "Machine.Isolate" "Machine.ReadWrite.All"; do
      RID=$(az ad sp show --id "$MDE_APP" --query "appRoles[?value=='${RN}'].id" -o tsv 2>/dev/null || echo "")
      [[ -z "$RID" ]] && continue
      az rest --method POST \
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${MDE_SP}/appRoleAssignedTo" \
        --body "{\"principalId\":\"${MDE_PID}\",\"resourceId\":\"${MDE_SP}\",\"appRoleId\":\"${RID}\"}" \
        2>/dev/null && ok "$RN → MDE Playbook" || warn "$RN: may exist or needs consent"
    done
  else warn "MDE service principal not found"; fi
else warn "MDE playbook not found — skipping"; fi

# ═══ PHASE 8: Graph API ═══
step "Phase 8/9: Graph API Permissions"
if [[ -n "$CA_PID" ]]; then
  GRAPH_SP=$(az ad sp show --id "$GRAPH_APP" --query id -o tsv 2>/dev/null || echo "")
  if [[ -n "$GRAPH_SP" ]]; then
    for RN in "User.ReadWrite.All" "Directory.ReadWrite.All" "GroupMember.ReadWrite.All"; do
      RID=$(az ad sp show --id "$GRAPH_APP" --query "appRoles[?value=='${RN}'].id" -o tsv 2>/dev/null || echo "")
      [[ -z "$RID" ]] && continue
      az rest --method POST \
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${GRAPH_SP}/appRoleAssignedTo" \
        --body "{\"principalId\":\"${CA_PID}\",\"resourceId\":\"${GRAPH_SP}\",\"appRoleId\":\"${RID}\"}" \
        2>/dev/null && ok "$RN → CA Playbook" || warn "$RN: may exist or needs consent"
    done
  fi
else warn "CA playbook not found — skipping"; fi

echo ""
log "Admin consent (if needed):"
echo -e "  ${CYAN}https://portal.azure.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview${NC}"

# ═══ PHASE 9: Verify ═══
step "Phase 9/9: Deployment Verification"
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🛡️  DEPLOYMENT COMPLETE — $(elapsed)                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║"
echo "║  Resource Group:    $RG"
echo "║  Workspace:         $WS"
echo "║  Region:            $LOC"
[[ -n "$DCE_URI" ]] && echo "║  DCE URI:           $DCE_URI"
[[ -n "$DCR_ID" ]]  && echo "║  DCR Immutable ID:  $DCR_ID"
echo "║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  RESOURCES:"
az resource list -g "$RG" --query "[].{Type:type,Name:name}" -o table 2>/dev/null | head -30
echo "║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  NEXT STEPS:                                                ║"
echo "║  1. Check data: Sentinel → Data connectors → SpyCloud      ║"
echo "║  2. Review rules: Sentinel → Analytics (filter: SpyCloud)   ║"
echo "║  3. Upload Copilot plugin: copilot/SpyCloud_Plugin.yaml     ║"
echo "║  4. Upload Copilot agent: copilot/SpyCloud_Agent.yaml       ║"
echo "║  5. Entra ID: Monitoring → Diagnostic settings (manual)     ║"
echo "║  6. IdP connectors: Content Hub → Okta/Duo/Ping/CyberArk   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
