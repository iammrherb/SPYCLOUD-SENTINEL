#!/usr/bin/env bash
#===============================================================================
#  SpyCloud Sentinel Supreme - QA Testing & Simulation Framework
#  Version: 2.0.0
#
#  Menu-driven tool for Cloud Shell. Covers:
#    1. Environment validation (workspace, DCE, DCR, tables, permissions)
#    2. Test data generation and ingestion
#    3. Analytics rule testing and simulation
#    4. Playbook and automation verification
#    5. Microsoft Defender for Endpoint (MDE) simulation
#    6. Conditional Access (CA) simulation
#    7. Copilot & Graph skill testing
#    8. Full QA report generation
#
#  Usage:
#    curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/spycloud-qa.sh | bash
#    OR
#    ./scripts/spycloud-qa.sh -g <resource-group> -w <workspace>
#===============================================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
step() { echo -e "\n${MAGENTA}${BOLD}=== $1 ===${NC}"; }

RG=""; WS=""; SUB=""; REPORT_FILE=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -g|--resource-group) RG="$2"; shift 2;;
    -w|--workspace) WS="$2"; shift 2;;
    -s|--subscription) SUB="$2"; shift 2;;
    -h|--help) head -20 "$0" | tail -19; exit 0;;
    *) shift;;
  esac
done

banner() {
  echo ""
  echo -e "${BOLD}============================================================${NC}"
  echo -e "${BOLD}  SpyCloud Sentinel Supreme -- QA Testing Framework v2.0   ${NC}"
  echo -e "${BOLD}============================================================${NC}"
}

prompt_config() {
  [[ -z "$RG" ]] && read -rp "Resource Group: " RG
  [[ -z "$WS" ]] && read -rp "Workspace Name: " WS
  echo -e "  RG: ${BOLD}${RG}${NC}  WS: ${BOLD}${WS}${NC}"
  REPORT_FILE="/tmp/spycloud-qa-$(date +%Y%m%d-%H%M%S).txt"
  echo "SpyCloud QA Report -- $(date)" > "$REPORT_FILE"
  echo "RG: $RG | WS: $WS" >> "$REPORT_FILE"
}

log_report() { echo "$1" >> "$REPORT_FILE"; }

get_ws_customer_id() {
  az monitor log-analytics workspace show -g "$RG" -n "$WS" --query customerId -o tsv 2>/dev/null
}

get_ws_resource_id() {
  az monitor log-analytics workspace show -g "$RG" -n "$WS" --query id -o tsv 2>/dev/null
}

get_dce_uri() {
  az monitor data-collection endpoint show -n "dce-spycloud-$WS" -g "$RG" \
    --query "logsIngestion.endpoint" -o tsv 2>/dev/null
}

get_dcr_id() {
  az monitor data-collection rule list -g "$RG" \
    --query "[?contains(name,'spycloud') || contains(name,'dcr-')].immutableId | [0]" -o tsv 2>/dev/null
}

get_monitor_token() {
  az account get-access-token --resource https://monitor.azure.com --query accessToken -o tsv 2>/dev/null
}

run_kql() {
  local ws_id="$1"; local query="$2"
  az monitor log-analytics query -w "$ws_id" --analytics-query "$query" -o json 2>/dev/null | python3 -c "
import sys,json
try:
    data=json.load(sys.stdin); rows=data.get('tables',[{}])[0].get('rows',[])
    print(f'{len(rows)} results' if rows else '0 results')
except: print('error')" 2>/dev/null
}

inject_logs() {
  local dce_uri="$1"; local dcr_id="$2"; local stream="$3"; local payload="$4"; local token="$5"
  curl -s -X POST \
    "${dce_uri}/dataCollectionRules/${dcr_id}/streams/${stream}?api-version=2023-01-01" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d "${payload}" -o /dev/null -w "%{http_code}" 2>/dev/null
}

# ==============================================================================
# 1. ENVIRONMENT VALIDATION
# ==============================================================================
validate_environment() {
  step "1. Environment Validation"
  log_report ""; log_report "=== ENVIRONMENT VALIDATION ==="

  az account show &>/dev/null || { fail "Not logged in. Run: az login"; return 1; }
  [[ -n "$SUB" ]] && az account set -s "$SUB"
  local tenant; tenant=$(az account show --query tenantId -o tsv)
  local sub_name; sub_name=$(az account show --query name -o tsv)
  ok "Subscription: $sub_name"; log_report "Subscription: $sub_name | Tenant: $tenant"

  local ws_id; ws_id=$(get_ws_resource_id)
  if [[ -n "$ws_id" ]]; then
    ok "Workspace: $WS"
    local ws_sku; ws_sku=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query sku.name -o tsv)
    local ws_retention; ws_retention=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query retentionInDays -o tsv)
    info "  SKU: $ws_sku | Retention: ${ws_retention}d"
    log_report "Workspace: $WS | SKU: $ws_sku | Retention: ${ws_retention}d"
  else
    fail "Workspace $WS not found"; log_report "Workspace: NOT FOUND"; return 1
  fi

  az rest --method GET \
    --uri "${ws_id}/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2023-02-01" \
    &>/dev/null \
    && { ok "Sentinel enabled"; log_report "Sentinel: enabled"; } \
    || { warn "Could not verify Sentinel status"; }

  local dce_uri; dce_uri=$(get_dce_uri)
  [[ -n "$dce_uri" ]] \
    && { ok "DCE: dce-spycloud-$WS -> $dce_uri"; log_report "DCE: $dce_uri"; } \
    || { fail "DCE not found"; log_report "DCE: NOT FOUND"; }

  local dcr_count; dcr_count=$(az monitor data-collection rule list -g "$RG" \
    --query "length([?contains(name,'spycloud') || contains(name,'dcr-')])" -o tsv 2>/dev/null)
  [[ "$dcr_count" -gt 0 ]] \
    && { ok "DCR: $dcr_count rule(s)"; log_report "DCR: $dcr_count"; } \
    || { warn "No SpyCloud DCR found"; log_report "DCR: NOT FOUND"; }

  echo ""; info "Checking custom tables..."
  local tables_found=0
  local ALL_TABLES=(SpyCloudBreachWatchlist_CL SpyCloudBreachCatalog_CL SpyCloudCompassData_CL
    SpyCloudCompassDevices_CL Spycloud_MDE_Logs_CL SpyCloud_ConditionalAccessLogs_CL
    SpyCloudCompassApplications_CL SpyCloudSipCookies_CL SpyCloudIdentityExposure_CL
    SpyCloudExposure_CL SpyCloudInvestigations_CL SpyCloudIdLink_CL SpyCloudCAP_CL
    SpyCloudDataPartnership_CL)
  for TABLE in "${ALL_TABLES[@]}"; do
    local exists; exists=$(az monitor log-analytics workspace table show \
      -g "$RG" -w "$WS" -n "$TABLE" --query name -o tsv 2>/dev/null)
    if [[ -n "$exists" ]]; then
      ok "  $TABLE"; tables_found=$((tables_found + 1))
    else
      warn "  $TABLE -- not found"
    fi
  done
  log_report "Tables found: $tables_found/14"

  echo ""; info "Checking Logic Apps (playbooks)..."
  local PLAYBOOKS=("SpyCloud-MDE-Remediation-$WS" "SpyCloud-CA-Remediation-$WS"
    "SpyCloud-CredResponse-$WS" "SpyCloud-MDE-Blocklist-$WS"
    "SpyCloud-ForcePasswordReset-$WS" "SpyCloud-RevokeSessions-$WS"
    "SpyCloud-IsolateDevice-$WS")
  for PB in "${PLAYBOOKS[@]}"; do
    local pb_state; pb_state=$(az logic workflow show -n "$PB" -g "$RG" --query state -o tsv 2>/dev/null)
    local pb_identity; pb_identity=$(az logic workflow show -n "$PB" -g "$RG" --query "identity.type" -o tsv 2>/dev/null)
    if [[ -n "$pb_state" ]]; then
      ok "  $PB: state=$pb_state identity=$pb_identity"
      log_report "Playbook $PB: state=$pb_state identity=$pb_identity"
    else
      warn "  $PB: not found"; log_report "Playbook $PB: NOT FOUND"
    fi
  done

  echo ""; info "Checking managed identity permissions..."
  local PERM_PB=("SpyCloud-MDE-Remediation-$WS" "SpyCloud-CA-Remediation-$WS" "SpyCloud-CredResponse-$WS")
  for PB in "${PERM_PB[@]}"; do
    local pid; pid=$(az logic workflow show -n "$PB" -g "$RG" --query "identity.principalId" -o tsv 2>/dev/null)
    [[ -z "$pid" ]] && continue
    local roles; roles=$(az role assignment list --assignee "$pid" \
      --query "[].roleDefinitionName" -o tsv 2>/dev/null | tr '\n' ', ')
    [[ -n "$roles" ]] && ok "  $PB roles: $roles" || warn "  $PB: no role assignments"
    log_report "  $PB roles: ${roles:-NONE}"
  done
}

# ==============================================================================
# 2. DATA GENERATION & INGESTION
# ==============================================================================
generate_and_ingest() {
  step "2. Test Data Generation & Ingestion"
  log_report ""; log_report "=== DATA GENERATION ==="

  if [[ ! -f "/tmp/generate-test-data.py" ]]; then
    curl -sL "https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/generate-test-data.py" \
      -o /tmp/generate-test-data.py
  fi

  info "Generating test data..."
  python3 /tmp/generate-test-data.py --output-json --output-dir /tmp/spycloud-test-data 2>/dev/null
  ok "Generated test data in /tmp/spycloud-test-data/"

  local dce_uri; dce_uri=$(get_dce_uri)
  [[ -z "$dce_uri" ]] && { fail "DCE not found"; return 1; }
  local dcr_id; dcr_id=$(get_dcr_id)
  [[ -z "$dcr_id" ]] && { fail "DCR not found"; return 1; }
  local token; token=$(get_monitor_token)
  [[ -z "$token" ]] && { fail "No Azure Monitor token"; return 1; }

  local ingested=0; local failed=0
  for file in /tmp/spycloud-test-data/*.json; do
    local table; table=$(basename "$file" .json)
    local cnt; cnt=$(python3 -c "import json; print(len(json.load(open('$file'))))" 2>/dev/null)
    echo -n "  $table ($cnt records): "
    local code; code=$(inject_logs "$dce_uri" "$dcr_id" "Custom-$table" "$(cat "$file")" "$token")
    if [[ "$code" == "204" || "$code" == "200" ]]; then
      echo -e "${GREEN}HTTP $code${NC}"; ingested=$((ingested + 1))
    else
      echo -e "${RED}HTTP $code${NC}"; failed=$((failed + 1))
    fi
    log_report "  $table: $cnt records -> HTTP $code"
  done
  ok "Ingested: $ingested | Failed: $failed"
  log_report "Ingestion: $ingested ok, $failed failed"
}

# ==============================================================================
# 3. ANALYTICS RULE TESTING
# ==============================================================================
test_analytics() {
  step "3. Analytics Rule Testing"
  log_report ""; log_report "=== ANALYTICS RULE TESTING ==="
  local ws_id; ws_id=$(get_ws_customer_id)
  info "Running 12 detection queries..."

  declare -A QUERIES
  QUERIES["Infostealer Detection"]="SpyCloudBreachWatchlist_CL | where severity >= 20 | summarize count() by severity"
  QUERIES["Plaintext Passwords"]="SpyCloudBreachWatchlist_CL | where isnotempty(password_plaintext) | summarize count()"
  QUERIES["VIP Exposures"]="SpyCloudBreachWatchlist_CL | where email has_any ('ceo','cfo','ciso','admin') | summarize count() by email"
  QUERIES["Stolen Cookies"]="SpyCloudSipCookies_CL | summarize Cookies=count(), Domains=dcount(cookie_domain) by email | top 5 by Cookies desc"
  QUERIES["Device Reinfection"]="SpyCloudCompassDevices_CL | summarize Infections=count() by user_hostname | where Infections > 1"
  QUERIES["MDE Isolation Audit"]="Spycloud_MDE_Logs_CL | summarize count() by Action, ActionStatus"
  QUERIES["CA Remediation Audit"]="SpyCloud_ConditionalAccessLogs_CL | summarize count() by Action, ActionStatus"
  QUERIES["Unremediated High-Sev"]="let remediated = SpyCloud_ConditionalAccessLogs_CL | distinct tolower(Email); SpyCloudBreachWatchlist_CL | where severity >= 20 | where tolower(email) !in (remediated) | summarize count()"
  QUERIES["Compass Overlap"]="SpyCloudCompassData_CL | join kind=inner (SpyCloudBreachWatchlist_CL | distinct email) on email | summarize count()"
  QUERIES["Risk Score Dist"]="SpyCloudExposure_CL | summarize count() by risk_level"
  QUERIES["Identity Links"]="SpyCloudIdLink_CL | summarize count() by link_type"
  QUERIES["CAP Policy Actions"]="SpyCloudCAP_CL | summarize count() by action_type, action_status"

  for name in "${!QUERIES[@]}"; do
    echo -n "  $name: "
    local result; result=$(run_kql "$ws_id" "${QUERIES[$name]}")
    if [[ "$result" == *"error"* || -z "$result" ]]; then
      echo -e "${YELLOW}no data${NC}"; log_report "  $name: no data"
    else
      echo -e "${GREEN}$result${NC}"; log_report "  $name: $result"
    fi
  done
}

# ==============================================================================
# 4. PLAYBOOK VERIFICATION
# ==============================================================================
test_playbooks() {
  step "4. Playbook & Automation Verification"
  log_report ""; log_report "=== PLAYBOOK VERIFICATION ==="

  local CHECK_PB=("SpyCloud-MDE-Remediation-$WS" "SpyCloud-CA-Remediation-$WS"
    "SpyCloud-CredResponse-$WS" "SpyCloud-MDE-Blocklist-$WS")
  for PB in "${CHECK_PB[@]}"; do
    local short_name; short_name=$(echo "$PB" | sed "s/-${WS}//")
    echo -n "  $short_name: "
    local state; state=$(az logic workflow show -n "$PB" -g "$RG" --query state -o tsv 2>/dev/null)
    if [[ -z "$state" ]]; then
      echo -e "${YELLOW}not deployed${NC}"; log_report "  $short_name: NOT DEPLOYED"; continue
    fi
    local identity; identity=$(az logic workflow show -n "$PB" -g "$RG" --query "identity.type" -o tsv 2>/dev/null)
    echo -e "state=${GREEN}$state${NC} identity=$identity"

    local last_run; last_run=$(az logic workflow list-runs -n "$PB" -g "$RG" \
      --query "[0].{status:status, time:startTime}" -o json 2>/dev/null)
    if [[ -n "$last_run" && "$last_run" != "[]" && "$last_run" != "null" ]]; then
      local run_status; run_status=$(echo "$last_run" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null)
      info "    Last run: $run_status"
    else
      info "    No runs yet"
    fi
    log_report "  $short_name: state=$state"
  done

  echo ""; info "Automation Rules:"
  local ws_rid; ws_rid=$(get_ws_resource_id)
  local auto_rules; auto_rules=$(az rest --method GET \
    --uri "${ws_rid}/providers/Microsoft.SecurityInsights/automationRules?api-version=2023-02-01" \
    2>/dev/null | python3 -c "
import sys,json
data=json.load(sys.stdin); rules=data.get('value',[])
for r in rules:
    name=r.get('properties',{}).get('displayName','?')
    enabled=r.get('properties',{}).get('triggeringLogic',{}).get('isEnabled',False)
    print(f'{name}|{enabled}')" 2>/dev/null)
  if [[ -n "$auto_rules" ]]; then
    while IFS='|' read -r name enabled; do
      [[ "$enabled" == "True" ]] && ok "  $name (enabled)" || warn "  $name (disabled)"
      log_report "  Automation: $name enabled=$enabled"
    done <<< "$auto_rules"
  else
    warn "  No automation rules found"
  fi
}

# ==============================================================================
# 5. MICROSOFT DEFENDER FOR ENDPOINT (MDE) SIMULATION
# ==============================================================================
simulate_mde() {
  step "5. Microsoft Defender for Endpoint (MDE) Simulation"
  log_report ""; log_report "=== MDE SIMULATION ==="
  info "Validates MDE integration by simulating device isolation workflow."

  local mde_pb="SpyCloud-MDE-Remediation-$WS"
  local mde_state; mde_state=$(az logic workflow show -n "$mde_pb" -g "$RG" --query state -o tsv 2>/dev/null)
  if [[ -z "$mde_state" ]]; then
    fail "MDE playbook not deployed: $mde_pb"; log_report "MDE: SKIP (not deployed)"; return 1
  fi
  ok "MDE playbook: state=$mde_state"

  local mde_pid; mde_pid=$(az logic workflow show -n "$mde_pb" -g "$RG" \
    --query "identity.principalId" -o tsv 2>/dev/null)
  if [[ -n "$mde_pid" ]]; then
    info "Checking MDE API permissions for principal: $mde_pid"
    local mde_perms; mde_perms=$(az rest --method GET \
      --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${mde_pid}/appRoleAssignments" \
      2>/dev/null | python3 -c "
import sys,json
try:
    data=json.load(sys.stdin); assignments=data.get('value',[])
    mde_roles=[]
    for a in assignments:
        rid=a.get('appRoleId','')
        if rid=='7438b122-aefc-4978-80ed-43db9fcc7571': mde_roles.append('Machine.ReadWrite.All')
        elif rid=='ea5a4a0a-f9c6-4e82-b1f3-8a5d60e87e2b': mde_roles.append('Machine.Read.All')
        elif rid=='93489bf5-0fbc-4f2d-b901-33f2fe08ff05': mde_roles.append('Machine.Isolate')
    print(','.join(mde_roles) if mde_roles else 'NONE')
except: print('CHECK_ERROR')" 2>/dev/null)
    if [[ "$mde_perms" == "NONE" || -z "$mde_perms" ]]; then
      warn "MDE playbook may lack required permissions (Machine.ReadWrite.All, Machine.Isolate)"
      info "Run: ./scripts/grant-permissions.sh -g $RG -w $WS"
      log_report "MDE Permissions: MISSING"
    else
      ok "MDE permissions: $mde_perms"; log_report "MDE Permissions: $mde_perms"
    fi
  fi

  echo ""; info "Simulating MDE isolation events via log ingestion..."
  local dce_uri; dce_uri=$(get_dce_uri)
  local dcr_id; dcr_id=$(get_dcr_id)
  if [[ -n "$dce_uri" && -n "$dcr_id" ]]; then
    local token; token=$(get_monitor_token)
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
    local test_payload; test_payload=$(python3 -c "
import json,sys
ts=\"${ts}\"
print(json.dumps([
  {'TimeGenerated':ts,'Action':'IsolateDevice','ActionStatus':'Simulated',
   'DeviceId':'sim-device-001','DeviceName':'DESKTOP-QA-MDE01',
   'Email':'qa-test@contoso.com','IncidentId':'sim-mde-001',
   'SpyCloudSeverity':25,'MalwareFamily':'RedLine','Source':'QA-Simulation'},
  {'TimeGenerated':ts,'Action':'SubmitIOC','ActionStatus':'Simulated',
   'DeviceId':'sim-device-002','DeviceName':'LAPTOP-QA-MDE02',
   'Email':'qa-admin@contoso.com','IncidentId':'sim-mde-002',
   'SpyCloudSeverity':20,'MalwareFamily':'Vidar','Source':'QA-Simulation'},
  {'TimeGenerated':ts,'Action':'TagDevice','ActionStatus':'Simulated',
   'DeviceId':'sim-device-003','DeviceName':'WORKSTATION-QA03',
   'Email':'qa-user@contoso.com','IncidentId':'sim-mde-003',
   'SpyCloudSeverity':22,'MalwareFamily':'Raccoon','Source':'QA-Simulation'}
]))" 2>/dev/null)
    local code; code=$(inject_logs "$dce_uri" "$dcr_id" "Custom-Spycloud_MDE_Logs_CL" "$test_payload" "$token")
    [[ "$code" == "204" || "$code" == "200" ]] \
      && { ok "MDE simulation logs injected (3 events, HTTP $code)"; log_report "MDE inject: HTTP $code"; } \
      || { warn "MDE simulation injection: HTTP $code"; log_report "MDE inject: HTTP $code"; }
  else
    warn "Cannot inject MDE simulation data (DCE/DCR not found)"
    log_report "MDE: SKIP (no DCE/DCR)"
  fi

  echo ""; info "Validating MDE detection queries..."
  local ws_id; ws_id=$(get_ws_customer_id)
  if [[ -n "$ws_id" ]]; then
    local mde_result; mde_result=$(run_kql "$ws_id" \
      "Spycloud_MDE_Logs_CL | where TimeGenerated > ago(1h) | summarize Total=count(), Simulated=countif(ActionStatus == 'Simulated') by Action")
    info "  MDE actions (last 1h): $mde_result"; log_report "MDE Query: $mde_result"

    info "Checking MDE device inventory correlation..."
    local device_result; device_result=$(run_kql "$ws_id" \
      "let infectedHosts=SpyCloudCompassDevices_CL | where TimeGenerated > ago(7d) | distinct user_hostname; DeviceInfo | where TimeGenerated > ago(24h) | where DeviceName in (infectedHosts) | summarize dcount(DeviceName)")
    info "  MDE device correlation: $device_result"; log_report "MDE Device Correlation: $device_result"
  fi
  ok "MDE simulation complete"
}

# ==============================================================================
# 6. CONDITIONAL ACCESS (CA) SIMULATION
# ==============================================================================
simulate_ca() {
  step "6. Conditional Access (CA) Simulation"
  log_report ""; log_report "=== CA SIMULATION ==="
  info "Validates Conditional Access integration workflow."

  local ca_pb="SpyCloud-CA-Remediation-$WS"
  local ca_state; ca_state=$(az logic workflow show -n "$ca_pb" -g "$RG" --query state -o tsv 2>/dev/null)
  if [[ -z "$ca_state" ]]; then
    fail "CA playbook not deployed: $ca_pb"; log_report "CA: SKIP (not deployed)"; return 1
  fi
  ok "CA playbook: state=$ca_state"

  local ca_pid; ca_pid=$(az logic workflow show -n "$ca_pb" -g "$RG" \
    --query "identity.principalId" -o tsv 2>/dev/null)
  if [[ -n "$ca_pid" ]]; then
    info "Checking Entra ID API permissions..."
    local ca_perms; ca_perms=$(az rest --method GET \
      --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${ca_pid}/appRoleAssignments" \
      2>/dev/null | python3 -c "
import sys,json
try:
    data=json.load(sys.stdin); assignments=data.get('value',[])
    roles=[]
    for a in assignments:
        rid=a.get('appRoleId','')
        if rid=='1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9': roles.append('User.ReadWrite.All')
        elif rid=='19dbc75e-c2e2-444c-a770-ec596d67b8ad': roles.append('Directory.ReadWrite.All')
        elif rid=='741f803b-c850-494e-b5df-cde7c675a1ca': roles.append('User.ManageIdentities.All')
        elif rid=='9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8': roles.append('RoleManagement.ReadWrite.Directory')
    print(','.join(roles) if roles else 'NONE')
except: print('CHECK_ERROR')" 2>/dev/null)
    if [[ "$ca_perms" == "NONE" || -z "$ca_perms" ]]; then
      warn "CA playbook may lack Entra ID permissions (User.ReadWrite.All, Directory.ReadWrite.All)"
      info "Run: ./scripts/grant-permissions.sh -g $RG -w $WS"
      log_report "CA Permissions: MISSING"
    else
      ok "CA permissions: $ca_perms"; log_report "CA Permissions: $ca_perms"
    fi
  fi

  echo ""; info "Simulating CA remediation events..."
  local dce_uri; dce_uri=$(get_dce_uri)
  local dcr_id; dcr_id=$(get_dcr_id)
  if [[ -n "$dce_uri" && -n "$dcr_id" ]]; then
    local token; token=$(get_monitor_token)
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
    local ca_payload; ca_payload=$(python3 -c "
import json,sys
ts=\"${ts}\"
print(json.dumps([
  {'TimeGenerated':ts,'Action':'ForcePasswordReset','ActionStatus':'Simulated',
   'Email':'qa-user1@contoso.com','UserId':'sim-user-001','IncidentId':'sim-ca-001',
   'SpyCloudSeverity':25,'RiskScore':85,'Source':'QA-Simulation'},
  {'TimeGenerated':ts,'Action':'RevokeSession','ActionStatus':'Simulated',
   'Email':'qa-user2@contoso.com','UserId':'sim-user-002','IncidentId':'sim-ca-002',
   'SpyCloudSeverity':20,'RiskScore':72,'Source':'QA-Simulation'},
  {'TimeGenerated':ts,'Action':'AddToCAGroup','ActionStatus':'Simulated',
   'Email':'qa-user3@contoso.com','UserId':'sim-user-003','IncidentId':'sim-ca-003',
   'SpyCloudSeverity':20,'RiskScore':65,'CAGroupName':'SpyCloud-HighRisk-MFA-Required',
   'Source':'QA-Simulation'},
  {'TimeGenerated':ts,'Action':'DisableAccount','ActionStatus':'Simulated',
   'Email':'qa-user4@contoso.com','UserId':'sim-user-004','IncidentId':'sim-ca-004',
   'SpyCloudSeverity':25,'RiskScore':92,'Source':'QA-Simulation'}
]))" 2>/dev/null)
    local code; code=$(inject_logs "$dce_uri" "$dcr_id" \
      "Custom-SpyCloud_ConditionalAccessLogs_CL" "$ca_payload" "$token")
    [[ "$code" == "204" || "$code" == "200" ]] \
      && { ok "CA simulation logs injected (4 events, HTTP $code)"; log_report "CA inject: HTTP $code"; } \
      || { warn "CA simulation injection: HTTP $code"; log_report "CA inject: HTTP $code"; }
  else
    warn "Cannot inject CA simulation data (DCE/DCR not found)"
    log_report "CA: SKIP (no DCE/DCR)"
  fi

  echo ""; info "Validating CA detection queries..."
  local ws_id; ws_id=$(get_ws_customer_id)
  if [[ -n "$ws_id" ]]; then
    local ca_result; ca_result=$(run_kql "$ws_id" \
      "SpyCloud_ConditionalAccessLogs_CL | where TimeGenerated > ago(1h) | summarize Actions=count() by Action, ActionStatus")
    info "  CA actions (last 1h): $ca_result"; log_report "CA Query: $ca_result"

    info "Checking SigninLogs correlation for exposed users..."
    local signin_result; signin_result=$(run_kql "$ws_id" \
      "let exposed=SpyCloudBreachWatchlist_CL | where severity >= 20 and TimeGenerated > ago(7d) | distinct email; SigninLogs | where TimeGenerated > ago(24h) | where UserPrincipalName in (exposed) | summarize SignIns=count(), FailedMFA=countif(ResultType != 0) by UserPrincipalName | top 5 by SignIns desc")
    info "  SigninLogs correlation: $signin_result"; log_report "CA SigninLogs: $signin_result"

    info "Checking unremediated high-severity exposures..."
    local unrem_result; unrem_result=$(run_kql "$ws_id" \
      "let remediated=SpyCloud_ConditionalAccessLogs_CL | where ActionStatus == 'Success' | distinct tolower(Email); SpyCloudBreachWatchlist_CL | where severity >= 20 and TimeGenerated > ago(7d) | where tolower(email) !in (remediated) | summarize Unremediated=count(), Users=dcount(email)")
    info "  Unremediated: $unrem_result"; log_report "CA Unremediated: $unrem_result"
  fi
  ok "CA simulation complete"
}

# ==============================================================================
# 7. COPILOT & GRAPH SKILL TESTING
# ==============================================================================
test_copilot() {
  step "7. Copilot & Graph Skill Validation"
  log_report ""; log_report "=== COPILOT & GRAPH VALIDATION ==="
  info "Validating Copilot plugin, agent, and Graph integration..."

  local script_dir; script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local repo_root="${script_dir}/.."

  local COPILOT_FILES=("copilot/SpyCloud_Plugin.yaml" "copilot/SpyCloud_Agent.yaml"
    "copilot/manifest.json" "copilot/SpyCloud_API_Plugin.yaml" ".vscode/mcp.json")
  for cf in "${COPILOT_FILES[@]}"; do
    [[ -f "$repo_root/$cf" ]] \
      && { ok "  Found: $cf"; log_report "  Copilot: $cf EXISTS"; } \
      || { warn "  Missing: $cf"; log_report "  Copilot: $cf MISSING"; }
  done

  echo ""; info "Validating KQL skill queries..."
  local ws_id; ws_id=$(get_ws_customer_id)

  declare -A SKILL_QUERIES
  SKILL_QUERIES["UserExposures"]="SpyCloudBreachWatchlist_CL | where isnotempty(email) | summarize count() by email | top 5 by count_"
  SKILL_QUERIES["DeviceForensics"]="SpyCloudCompassDevices_CL | summarize count() by user_hostname | top 5 by count_"
  SKILL_QUERIES["BreachCatalog"]="SpyCloudBreachCatalog_CL | summarize count() by breach_title | top 5 by count_"
  SKILL_QUERIES["StolenCookies"]="SpyCloudSipCookies_CL | summarize count() by cookie_domain | top 5 by count_"
  SKILL_QUERIES["ConnectorHealth"]="union isfuzzy=true SpyCloudBreachWatchlist_CL, SpyCloudBreachCatalog_CL, SpyCloudCompassData_CL | where TimeGenerated > ago(24h) | summarize Records=count(), Latest=max(TimeGenerated) by Type"
  SKILL_QUERIES["IdentityLinks"]="SpyCloudIdLink_CL | summarize count() by link_type"
  SKILL_QUERIES["MDE-Correlation"]="Spycloud_MDE_Logs_CL | summarize count() by Action, ActionStatus"
  SKILL_QUERIES["CA-Remediation"]="SpyCloud_ConditionalAccessLogs_CL | summarize count() by Action, ActionStatus"
  SKILL_QUERIES["RiskScoreEngine"]="SpyCloudExposure_CL | summarize avg(risk_score), max(risk_score), min(risk_score)"

  for skill in "${!SKILL_QUERIES[@]}"; do
    echo -n "  $skill: "
    local result; result=$(run_kql "$ws_id" "${SKILL_QUERIES[$skill]}")
    if [[ "$result" == *"error"* || -z "$result" ]]; then
      echo -e "${YELLOW}no data${NC}"; log_report "  Skill $skill: no data"
    else
      echo -e "${GREEN}$result${NC}"; log_report "  Skill $skill: $result"
    fi
  done

  echo ""; info "Sentinel Graph MCP Server:"
  info "  URL: https://sentinel.microsoft.com/mcp/graph"
  info "  Tools: graph_exposure_perimeter, graph_find_blastRadius, graph_find_walkable_paths"
  info "  Setup: Run ./scripts/setup-sentinel-graph.sh for automated configuration"
  log_report "Graph MCP: sentinel.microsoft.com/mcp/graph"
  ok "Copilot & Graph validation complete"
}

# ==============================================================================
# 8. FULL QA REPORT
# ==============================================================================
generate_report() {
  step "8. Full QA Report"
  local ws_id; ws_id=$(get_ws_customer_id)
  log_report ""; log_report "=== FULL QA REPORT ==="
  log_report "Generated: $(date)"

  info "Querying data volumes..."
  local volume_query="union isfuzzy=true "
  volume_query+="(SpyCloudBreachWatchlist_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Watchlist'), "
  volume_query+="(SpyCloudBreachCatalog_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Catalog'), "
  volume_query+="(SpyCloudCompassData_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Compass'), "
  volume_query+="(SpyCloudCompassDevices_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Devices'), "
  volume_query+="(Spycloud_MDE_Logs_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='MDE'), "
  volume_query+="(SpyCloud_ConditionalAccessLogs_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='CA'), "
  volume_query+="(SpyCloudSipCookies_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='SIP'), "
  volume_query+="(SpyCloudIdLink_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='IdLink'), "
  volume_query+="(SpyCloudExposure_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Exposure') "
  volume_query+="| project Table, Records, Latest"
  az monitor log-analytics query -w "$ws_id" --analytics-query "$volume_query" -o table 2>/dev/null

  info "Checking incidents..."
  local ws_rid; ws_rid=$(get_ws_resource_id)
  az rest --method GET \
    --uri "${ws_rid}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01&\$top=100" \
    2>/dev/null | python3 -c "
import sys,json
data=json.load(sys.stdin); incidents=data.get('value',[])
spycloud=[i for i in incidents if 'SpyCloud' in i.get('properties',{}).get('title','') or 'spycloud' in json.dumps(i).lower()]
print(f'Total: {len(incidents)} | SpyCloud: {len(spycloud)}')
for i in spycloud[:5]:
    p=i.get('properties',{})
    sev=p.get('severity','?'); status=p.get('status','?'); title=p.get('title','?')[:60]
    print(f'  {sev} | {status} | {title}')" 2>/dev/null

  echo ""
  echo -e "${GREEN}${BOLD}=== QA Report saved: $REPORT_FILE ===${NC}"
  cat "$REPORT_FILE"
}

# ==============================================================================
# MAIN MENU
# ==============================================================================
main_menu() {
  banner
  prompt_config

  while true; do
    echo ""
    echo -e "${BOLD}Select an option:${NC}"
    echo "  1) Validate Environment (workspace, DCE, DCR, tables, permissions)"
    echo "  2) Generate & Ingest Test Data (records across 14 tables)"
    echo "  3) Test Analytics Rules (12 detection queries)"
    echo "  4) Verify Playbooks & Automation (state, identity, runs)"
    echo "  5) Simulate MDE Integration (device isolation, IOC, tagging)"
    echo "  6) Simulate CA Integration (password reset, session revoke, group add)"
    echo "  7) Validate Copilot & Graph Skills (KQL queries, MCP config)"
    echo "  8) Generate Full QA Report"
    echo "  9) Run ALL (1-8 in sequence)"
    echo "  p) Grant Playbook API Permissions"
    echo "  q) Quit"
    echo ""
    read -rp "Choice [1-9/p/q]: " choice

    case $choice in
      1) validate_environment;;
      2) generate_and_ingest;;
      3) test_analytics;;
      4) test_playbooks;;
      5) simulate_mde;;
      6) simulate_ca;;
      7) test_copilot;;
      8) generate_report;;
      9) validate_environment
         generate_and_ingest
         info "Waiting 30s for log ingestion..."
         sleep 30
         test_analytics
         test_playbooks
         simulate_mde
         simulate_ca
         test_copilot
         generate_report
         ;;
      p) curl -sL "https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/grant-permissions.sh" \
           | bash -s -- -g "$RG" -w "$WS";;
      q|Q) echo "Bye!"; exit 0;;
      *) warn "Invalid choice";;
    esac
  done
}

main_menu
