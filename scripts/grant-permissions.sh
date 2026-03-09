#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════
#  SpyCloud Sentinel — Grant API Permissions
#  Lightweight script — only does what ARM templates cannot:
#    1. MDE API permissions (Machine.Isolate, Machine.ReadWrite.All)
#    2. Graph API permissions (User.ReadWrite.All, Directory.ReadWrite.All)
#
#  RBAC roles (Monitoring Metrics Publisher, Sentinel Responder) are
#  handled by ARM template role assignments — no script needed.
#
#  Usage:
#    curl -sL .../scripts/grant-permissions.sh | bash -s -- -g RG -w WS
#    OR
#    ./scripts/grant-permissions.sh -g my-resource-group -w my-workspace
#═══════════════════════════════════════════════════════════════════
set -uo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok(){ echo -e "${GREEN}✅${NC} $1"; }
warn(){ echo -e "${YELLOW}⚠️${NC}  $1"; }
err(){ echo -e "${RED}❌${NC} $1"; }

RG=""; WS=""
while [[ $# -gt 0 ]]; do
  case $1 in
    -g|--resource-group) RG="$2"; shift 2;;
    -w|--workspace) WS="$2"; shift 2;;
    -h|--help) head -12 "$0" | tail -11; exit 0;;
    *) err "Unknown: $1"; exit 1;;
  esac
done
[[ -z "$RG" || -z "$WS" ]] && { err "Required: -g <resource-group> -w <workspace>"; exit 1; }

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║  SpyCloud Sentinel — Grant API Permissions     ║"
echo "╚════════════════════════════════════════════════╝"
echo "  RG: $RG  WS: $WS"
echo ""

# Check login
az account show &>/dev/null || { warn "Not logged in — running az login..."; az login; }

MDE_APP="fc780465-2017-40d4-a0c5-307022471b92"
GRAPH_APP="00000003-0000-0000-c000-000000000000"

grant_app_role() {
  local PB_NAME="$1" APP_ID="$2" PERM="$3"
  local PID=$(az logic workflow show --name "$PB_NAME" -g "$RG" --query "identity.principalId" -o tsv 2>/dev/null) || true
  [[ -z "$PID" ]] && { warn "$PB_NAME: not found (skipping)"; return; }
  
  local SP_ID=$(az ad sp show --id "$APP_ID" --query "id" -o tsv 2>/dev/null) || true
  [[ -z "$SP_ID" ]] && { err "Service principal $APP_ID not found"; return; }
  
  local ROLE_ID=$(az ad sp show --id "$APP_ID" --query "appRoles[?value=='$PERM'].id | [0]" -o tsv 2>/dev/null) || true
  [[ -z "$ROLE_ID" ]] && { err "Permission $PERM not found on $APP_ID"; return; }
  
  az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo" \
    --body "{\"principalId\":\"$PID\",\"resourceId\":\"$SP_ID\",\"appRoleId\":\"$ROLE_ID\"}" \
    2>/dev/null && ok "$PERM → $PB_NAME" || warn "$PERM → $PB_NAME (may already exist)"
}

echo "── MDE API Permissions ──"
for PB in "SpyCloud-MDE-Remediation-$WS" "SpyCloud-MDE-Blocklist-$WS"; do
  grant_app_role "$PB" "$MDE_APP" "Machine.Isolate"
  grant_app_role "$PB" "$MDE_APP" "Machine.ReadWrite.All"
done

echo ""
echo "── Graph API Permissions ──"
for PB in "SpyCloud-CA-Remediation-$WS" "SpyCloud-CredResponse-$WS"; do
  grant_app_role "$PB" "$GRAPH_APP" "User.ReadWrite.All"
  grant_app_role "$PB" "$GRAPH_APP" "Directory.ReadWrite.All"
done

echo ""
echo "── Admin Consent ──"
echo "  Grant admin consent in Entra ID → Enterprise Applications → Managed Identities"
echo "  Find each SpyCloud Logic App → Permissions → Grant admin consent"
echo ""
ok "Done. Verify: Sentinel → Logic Apps → check each playbook runs"
