#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1"; }
ok()  { echo -e "${GREEN}  ✅ $1${NC}"; }
warn(){ echo -e "${YELLOW}  ⚠️  $1${NC}"; }
err() { echo -e "${RED}  ❌ $1${NC}"; }

RG="" ; WS=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -g|--resource-group) RG="$2"; shift 2;;
        -w|--workspace) WS="$2"; shift 2;;
        -h|--help) echo "Usage: $0 -g <resource-group> -w <workspace>"; exit 0;;
        *) echo "Unknown: $1"; exit 1;;
    esac
done
[[ -z "$RG" || -z "$WS" ]] && { echo "Usage: $0 -g <rg> -w <ws>"; exit 1; }

echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║  🛡️  SpyCloud Sentinel — Post-Deploy Config      ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# Check login
log "Checking Azure CLI login..."
az account show --query "{Sub:name,Tenant:tenantId}" -o table || { az login; }

# Resolve DCE
log "Resolving DCE Logs Ingestion URI..."
DCE=$(az monitor data-collection endpoint show --name "dce-spycloud-${WS}" -g "$RG" --query "logsIngestion.endpoint" -o tsv 2>/dev/null || echo "")
[[ -n "$DCE" ]] && ok "DCE URI: $DCE" || { warn "DCE not found yet — waiting 60s..."; sleep 60; DCE=$(az monitor data-collection endpoint show --name "dce-spycloud-${WS}" -g "$RG" --query "logsIngestion.endpoint" -o tsv 2>/dev/null || echo ""); [[ -n "$DCE" ]] && ok "DCE URI: $DCE" || err "DCE still not available"; }

# Resolve DCR
log "Resolving DCR Immutable ID..."
DCR=$(az monitor data-collection rule show --name "dcr-spycloud-${WS}" -g "$RG" --query "immutableId" -o tsv 2>/dev/null || echo "")
[[ -n "$DCR" ]] && ok "DCR ID: $DCR" || { warn "DCR not found yet — waiting 60s..."; sleep 60; DCR=$(az monitor data-collection rule show --name "dcr-spycloud-${WS}" -g "$RG" --query "immutableId" -o tsv 2>/dev/null || echo ""); [[ -n "$DCR" ]] && ok "DCR ID: $DCR" || err "DCR still not available"; }

# RBAC: Monitoring Metrics Publisher
log "Assigning Monitoring Metrics Publisher..."
DCR_RID=$(az monitor data-collection rule show --name "dcr-spycloud-${WS}" -g "$RG" --query id -o tsv 2>/dev/null || echo "")
ROLE="3913510d-42f4-4e42-8a64-420c390055eb"
for LA in "SpyCloud-MDE-Remediation-${WS}" "SpyCloud-CA-Remediation-${WS}"; do
    PID=$(az logic workflow show --name "$LA" -g "$RG" --query "identity.principalId" -o tsv 2>/dev/null || echo "")
    if [[ -n "$PID" && -n "$DCR_RID" ]]; then
        az role assignment create --assignee-object-id "$PID" --assignee-principal-type ServicePrincipal --role "$ROLE" --scope "$DCR_RID" 2>/dev/null && ok "RBAC: $LA" || warn "May already exist: $LA"
    else
        warn "Skipping $LA (not found)"
    fi
done

# Summary
echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║  ✅ POST-DEPLOY COMPLETE                         ║"
echo "╠═══════════════════════════════════════════════════╣"
[[ -n "$DCE" ]] && echo "║  DCE: $DCE"
[[ -n "$DCR" ]] && echo "║  DCR: $DCR"
echo "╠═══════════════════════════════════════════════════╣"
echo "║  REMAINING MANUAL STEPS:                          ║"
echo "║  1. MDE Logic App → Identity → Add permissions:   ║"
echo "║     Machine.Isolate, Machine.ReadWrite.All        ║"
echo "║  2. CA Logic App → Identity → Add permissions:    ║"
echo "║     User.ReadWrite.All, Directory.ReadWrite.All   ║"
echo "║  3. Review analytics rules: Sentinel → Analytics  ║"
echo "║  4. Upload Copilot files from copilot/ directory  ║"
echo "║  5. Configure Entra ID diagnostic settings        ║"
echo "╚═══════════════════════════════════════════════════╝"
