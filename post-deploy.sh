#!/usr/bin/env bash
#
# SpyCloud Sentinel — Post-Deployment Configuration
# Resolves DCE/DCR values and assigns RBAC permissions
# NO POWERSHELL REQUIRED — pure Azure CLI
#
# Usage:
#   ./post-deploy.sh --resource-group spycloud-sentinel --workspace spycloud-ws
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }

# Parse arguments
RESOURCE_GROUP=""
WORKSPACE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --resource-group|-g) RESOURCE_GROUP="$2"; shift 2 ;;
        --workspace|-w) WORKSPACE="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 --resource-group <name> --workspace <name>"
            echo ""
            echo "Options:"
            echo "  -g, --resource-group    Azure resource group name"
            echo "  -w, --workspace         Log Analytics workspace name"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$RESOURCE_GROUP" ] || [ -z "$WORKSPACE" ]; then
    log_error "Both --resource-group and --workspace are required"
    echo "Usage: $0 --resource-group <name> --workspace <name>"
    exit 1
fi

DCE_NAME="dce-spycloud-${WORKSPACE}"
DCR_NAME="dcr-spycloud-${WORKSPACE}"
MDE_PLAYBOOK="SpyCloud-MDE-Remediation-${WORKSPACE}"
CA_PLAYBOOK="SpyCloud-CA-Remediation-${WORKSPACE}"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  SpyCloud Sentinel — Post-Deploy Configuration  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
log_info "Resource Group: ${RESOURCE_GROUP}"
log_info "Workspace: ${WORKSPACE}"

# ============================================================
# Step 1: Verify Azure CLI login
# ============================================================
log_step "Step 1: Verify Azure Login"

if ! az account show &>/dev/null; then
    log_warn "Not logged in. Running 'az login'..."
    az login
fi

SUBSCRIPTION=$(az account show --query name -o tsv)
TENANT=$(az account show --query tenantId -o tsv)
log_ok "Subscription: ${SUBSCRIPTION}"
log_ok "Tenant: ${TENANT}"

# ============================================================
# Step 2: Resolve DCE Logs Ingestion URI
# ============================================================
log_step "Step 2: Resolve DCE Logs Ingestion URI"

DCE_URI=$(az monitor data-collection endpoint show \
    --name "${DCE_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query "logsIngestion.endpoint" \
    -o tsv 2>/dev/null || echo "")

if [ -n "$DCE_URI" ]; then
    log_ok "DCE URI: ${DCE_URI}"
else
    log_error "Could not resolve DCE URI for '${DCE_NAME}'"
    log_info "Check: az monitor data-collection endpoint list -g ${RESOURCE_GROUP} -o table"
    exit 1
fi

# ============================================================
# Step 3: Resolve DCR Immutable ID
# ============================================================
log_step "Step 3: Resolve DCR Immutable ID"

DCR_ID=$(az monitor data-collection rule show \
    --name "${DCR_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query "immutableId" \
    -o tsv 2>/dev/null || echo "")

if [ -n "$DCR_ID" ]; then
    log_ok "DCR Immutable ID: ${DCR_ID}"
else
    log_warn "DCR '${DCR_NAME}' not found yet (content template may still be deploying)"
    log_info "Waiting 60 seconds and retrying..."
    sleep 60
    
    DCR_ID=$(az monitor data-collection rule show \
        --name "${DCR_NAME}" \
        --resource-group "${RESOURCE_GROUP}" \
        --query "immutableId" \
        -o tsv 2>/dev/null || echo "")
    
    if [ -n "$DCR_ID" ]; then
        log_ok "DCR Immutable ID: ${DCR_ID}"
    else
        log_error "DCR still not available. You may need to wait a few more minutes."
        log_info "Run this script again after the Sentinel content package finishes deploying."
        exit 1
    fi
fi

# ============================================================
# Step 4: Assign Monitoring Metrics Publisher role
# ============================================================
log_step "Step 4: Assign Monitoring Metrics Publisher"

MONITORING_PUBLISHER_ROLE="3913510d-42f4-4e42-8a64-420c390055eb"

DCR_RESOURCE_ID=$(az monitor data-collection rule show \
    --name "${DCR_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query "id" -o tsv 2>/dev/null || echo "")

for PLAYBOOK_NAME in "${MDE_PLAYBOOK}" "${CA_PLAYBOOK}"; do
    PRINCIPAL_ID=$(az logic workflow show \
        --name "${PLAYBOOK_NAME}" \
        --resource-group "${RESOURCE_GROUP}" \
        --query "identity.principalId" \
        -o tsv 2>/dev/null || echo "")
    
    if [ -n "$PRINCIPAL_ID" ] && [ -n "$DCR_RESOURCE_ID" ]; then
        az role assignment create \
            --assignee-object-id "${PRINCIPAL_ID}" \
            --assignee-principal-type ServicePrincipal \
            --role "${MONITORING_PUBLISHER_ROLE}" \
            --scope "${DCR_RESOURCE_ID}" \
            2>/dev/null && log_ok "Assigned to ${PLAYBOOK_NAME}" || log_warn "May already exist for ${PLAYBOOK_NAME}"
    else
        log_warn "Skipping ${PLAYBOOK_NAME} (not found or no identity)"
    fi
done

# ============================================================
# Step 5: Verify Data Connector Health
# ============================================================
log_step "Step 5: Verify Deployment"

echo ""
echo "Resources in ${RESOURCE_GROUP}:"
az resource list \
    --resource-group "${RESOURCE_GROUP}" \
    --query "[].{Type:type, Name:name}" \
    -o table

# ============================================================
# Summary
# ============================================================

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ✅ POST-DEPLOYMENT COMPLETE                        ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  DCE URI:          ${DCE_URI}"
echo "║  DCR Immutable ID: ${DCR_ID}"
echo "║                                                      ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  REMAINING MANUAL STEPS:                             ║"
echo "║                                                      ║"
echo "║  1. MDE Playbook API Permissions:                    ║"
echo "║     Portal → Logic App → Identity → Add:             ║"
echo "║     • Machine.Isolate                                ║"
echo "║     • Machine.ReadWrite.All                          ║"
echo "║                                                      ║"
echo "║  2. CA Playbook Graph Permissions:                   ║"
echo "║     Portal → Logic App → Identity → Add:             ║"
echo "║     • User.ReadWrite.All                             ║"
echo "║     • Directory.ReadWrite.All                        ║"
echo "║                                                      ║"
echo "║  3. Review & enable analytics rules:                 ║"
echo "║     Sentinel → Analytics → Active rules              ║"
echo "║                                                      ║"
echo "║  4. Upload Security Copilot files:                   ║"
echo "║     • copilot/SpyCloud_Plugin.yaml → Sources         ║"
echo "║     • copilot/SpyCloud_Agent.yaml → Build            ║"
echo "║                                                      ║"
echo "║  5. Configure Entra ID diagnostic settings:          ║"
echo "║     Entra ID → Monitoring → Diagnostic settings      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
