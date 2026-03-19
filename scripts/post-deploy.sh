#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#  SpyCloud Sentinel — Complete Post-Deployment Configuration
#  Version: 4.0.0
#
#  Completes everything ARM templates cannot:
#    Phase 1: Azure authentication
#    Phase 2: Resolve DCE Logs Ingestion URI
#    Phase 3: Resolve DCR Immutable ID
#    Phase 4: RBAC — Monitoring Metrics Publisher on DCR
#    Phase 5: MDE API permissions (Machine.Isolate, Machine.ReadWrite.All)
#    Phase 6: Graph API permissions (User.ReadWrite.All, Directory.ReadWrite.All)
#    Phase 7: Admin consent + deployment verification
#
#  Usage:
#    chmod +x scripts/post-deploy.sh
#    ./scripts/post-deploy.sh -g spycloud-sentinel -w spycloud-ws
#═══════════════════════════════════════════════════════════════════════════════
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

RG="";WS="";SUB="";SKIP_MDE=false;SKIP_GRAPH=false;DRY=false
while [[ $# -gt 0 ]]; do
  case $1 in
    -g|--resource-group)RG="$2";shift 2;;-w|--workspace)WS="$2";shift 2;;
    -s|--subscription)SUB="$2";shift 2;;--skip-mde)SKIP_MDE=true;shift;;
    --skip-graph)SKIP_GRAPH=true;shift;;--dry-run)DRY=true;shift;;
    -h|--help)head -15 "$0"|tail -14;exit 0;;*)err "Unknown: $1";exit 1;;
  esac
done
[[ -z "$RG" || -z "$WS" ]] && { err "Required: -g <rg> -w <ws>"; exit 1; }

DCE_NAME="dce-spycloud-${WS}";DCR_NAME="dcr-spycloud-${WS}"
MDE_PB="SpyCloud-MDE-Remediation-${WS}";CA_PB="SpyCloud-CA-Remediation-${WS}"
MDE_APP="fc780465-2017-40d4-a0c5-307022471b92";GRAPH_APP="00000003-0000-0000-c000-000000000000"
MON_ROLE="3913510d-42f4-4e42-8a64-420c390055eb"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  🛡️  SpyCloud Sentinel — Post-Deploy Configuration     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "  RG: ${BOLD}${RG}${NC}  WS: ${BOLD}${WS}${NC}  Dry: ${DRY}"

# Phase 1: Auth
step "Phase 1/7: Authentication"
az account show &>/dev/null || { warn "Logging in..."; az login; }
[[ -n "$SUB" ]] && az account set -s "$SUB"
TENANT=$(az account show --query tenantId -o tsv)
SUBID=$(az account show --query id -o tsv)
ok "Sub: $(az account show --query name -o tsv) | Tenant: ${TENANT}"

# Phase 2: DCE
step "Phase 2/7: Resolve DCE"
DCE_URI=""
for i in 1 2 3; do
  DCE_URI=$(az monitor data-collection endpoint show --name "$DCE_NAME" -g "$RG" --query "logsIngestion.endpoint" -o tsv 2>/dev/null||echo "")
  [[ -n "$DCE_URI" ]] && { ok "DCE: $DCE_URI"; break; }
  [[ $i -lt 3 ]] && { warn "Attempt $i/3 — waiting 30s..."; sleep 30; }
done
[[ -z "$DCE_URI" ]] && err "DCE not found"

# Phase 3: DCR
step "Phase 3/7: Resolve DCR"
DCR_ID="";DCR_RID=""
for i in 1 2 3; do
  DCR_ID=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" --query "immutableId" -o tsv 2>/dev/null||echo "")
  [[ -n "$DCR_ID" ]] && { DCR_RID=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" --query id -o tsv); ok "DCR: $DCR_ID"; break; }
  [[ $i -lt 3 ]] && { warn "Attempt $i/3 — waiting 45s..."; sleep 45; }
done
[[ -z "$DCR_ID" ]] && err "DCR not found — content template may still be deploying"

# Phase 4: RBAC
step "Phase 4/7: RBAC — Monitoring Metrics Publisher"
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

# Phase 5: MDE API
step "Phase 5/7: MDE API Permissions"
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

# Phase 6: Graph API
step "Phase 6/7: Graph API Permissions"
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

# Phase 7: Verify
step "Phase 7/7: Verification"
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  DEPLOYMENT STATUS                                      ║"
echo "╠══════════════════════════════════════════════════════════╣"
verify(){ local n="$1";local c="$2"; $c &>/dev/null && echo "║  ✅ $n" || echo "║  ⚠️  $n"; }
verify "Workspace: ${WS}" "az monitor log-analytics workspace show --workspace-name ${WS} -g ${RG}"
[[ -n "$DCE_URI" ]] && echo "║  ✅ DCE: ${DCE_URI}" || echo "║  ❌ DCE not resolved"
[[ -n "$DCR_ID" ]]  && echo "║  ✅ DCR: ${DCR_ID}" || echo "║  ❌ DCR not resolved"
verify "MDE Playbook" "az logic workflow show --name ${MDE_PB} -g ${RG}"
verify "CA Playbook" "az logic workflow show --name ${CA_PB} -g ${RG}"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  REMAINING OPTIONAL STEPS:                              ║"
echo "║  1. Upload copilot/SpyCloud_Plugin.yaml → Copilot Sources"
echo "║  2. Upload copilot/SpyCloud_Agent.yaml → Copilot Build  "
echo "║  3. Configure Entra ID → Monitoring → Diagnostic settings"
echo "║  4. Install IdP connectors: Okta/Duo/Ping/CyberArk     "
echo "║  5. Review & enable analytics rules in Sentinel          "
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
