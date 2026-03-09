#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════
#  SpyCloud Sentinel — Grant Playbook API Permissions
#  
#  Run this ONLY when you're ready to enable automated remediation.
#  The data pipeline (connector, rules, workbook) works without this.
#
#  Usage: ./scripts/grant-permissions.sh -g my-rg -w my-workspace
#═══════════════════════════════════════════════════════════════════
set -uo pipefail
RG=""; WS=""
while [[ $# -gt 0 ]]; do
  case $1 in -g) RG="$2"; shift 2;; -w) WS="$2"; shift 2;; *) shift;; esac
done
[[ -z "$RG" || -z "$WS" ]] && { echo "Usage: $0 -g <resource-group> -w <workspace>"; exit 1; }

az account show &>/dev/null || az login

grant() {
  local PB="$1" APP="$2" PERM="$3"
  local PID=$(az logic workflow show -n "$PB" -g "$RG" --query identity.principalId -o tsv 2>/dev/null) || return
  [[ -z "$PID" ]] && { echo "  ⏭ $PB not found"; return; }
  local SPID=$(az ad sp show --id "$APP" --query id -o tsv 2>/dev/null)
  local RID=$(az ad sp show --id "$APP" --query "appRoles[?value=='$PERM'].id|[0]" -o tsv 2>/dev/null)
  [[ -z "$RID" ]] && { echo "  ⏭ $PERM not found"; return; }
  az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SPID/appRoleAssignedTo" \
    --body "{\"principalId\":\"$PID\",\"resourceId\":\"$SPID\",\"appRoleId\":\"$RID\"}" 2>/dev/null \
    && echo "  ✅ $PERM → $PB" || echo "  ⚠️ $PERM → $PB (may exist)"
}

MDE="fc780465-2017-40d4-a0c5-307022471b92"
GRAPH="00000003-0000-0000-c000-000000000000"

echo "MDE Permissions:"
for PB in "SpyCloud-MDE-Remediation-$WS" "SpyCloud-MDE-Blocklist-$WS"; do
  grant "$PB" "$MDE" "Machine.Isolate"
  grant "$PB" "$MDE" "Machine.ReadWrite.All"
done

echo "Graph Permissions:"
for PB in "SpyCloud-CA-Remediation-$WS" "SpyCloud-CredResponse-$WS"; do
  grant "$PB" "$GRAPH" "User.ReadWrite.All"
  grant "$PB" "$GRAPH" "Directory.ReadWrite.All"
done

echo "Done. Grant admin consent: Entra ID → Enterprise Apps → Managed Identities"
