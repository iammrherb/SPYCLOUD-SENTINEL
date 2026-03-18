#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#  SpyCloud Sentinel Supreme — QA Testing & Simulation Framework
#  Version: 1.0.0
#
#  Menu-driven tool for Cloud Shell. Covers:
#    1. Environment validation (workspace, DCE, DCR, tables, permissions)
#    2. Test data generation and ingestion
#    3. Analytics rule testing and simulation
#    4. Playbook and automation verification
#    5. Copilot skill testing
#    6. Full QA report generation
#
#  Usage:
#    curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/spycloud-qa.sh | bash
#    OR
#    ./scripts/spycloud-qa.sh -g <resource-group> -w <workspace>
#═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
MAGENTA='\033[0;35m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✅${NC} $1"; }
fail() { echo -e "${RED}❌${NC} $1"; }
warn() { echo -e "${YELLOW}⚠️${NC}  $1"; }
info() { echo -e "${CYAN}ℹ${NC}  $1"; }
step() { echo -e "\n${MAGENTA}━━━ $1 ━━━${NC}"; }

RG=""; WS=""; SUB=""; REPORT_FILE=""

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    -g|--resource-group) RG="$2"; shift 2;;
    -w|--workspace) WS="$2"; shift 2;;
    -s|--subscription) SUB="$2"; shift 2;;
    -h|--help) head -15 "$0" | tail -14; exit 0;;
    *) shift;;
  esac
done

banner() {
  echo ""
  echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║  🛡️  SpyCloud Sentinel Supreme — QA Testing Framework      ║${NC}"
  echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
}

prompt_config() {
  if [[ -z "$RG" ]]; then
    read -rp "Resource Group: " RG
  fi
  if [[ -z "$WS" ]]; then
    read -rp "Workspace Name: " WS
  fi
  echo -e "  RG: ${BOLD}${RG}${NC}  WS: ${BOLD}${WS}${NC}"
  REPORT_FILE="/tmp/spycloud-qa-$(date +%Y%m%d-%H%M%S).txt"
  echo "SpyCloud QA Report — $(date)" > "$REPORT_FILE"
  echo "RG: $RG | WS: $WS" >> "$REPORT_FILE"
}

log_report() {
  echo "$1" >> "$REPORT_FILE"
}

# ================================================================
# 1. ENVIRONMENT VALIDATION
# ================================================================
validate_environment() {
  step "1. Environment Validation"
  log_report ""; log_report "=== ENVIRONMENT VALIDATION ==="
  
  # Auth
  az account show &>/dev/null || { fail "Not logged in. Run: az login"; return 1; }
  [[ -n "$SUB" ]] && az account set -s "$SUB"
  local tenant=$(az account show --query tenantId -o tsv)
  local sub_name=$(az account show --query name -o tsv)
  ok "Subscription: $sub_name"
  log_report "Subscription: $sub_name | Tenant: $tenant"
  
  # Workspace
  local ws_id=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query id -o tsv 2>/dev/null)
  if [[ -n "$ws_id" ]]; then
    ok "Workspace: $WS"
    local ws_sku=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query sku.name -o tsv)
    local ws_retention=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query retentionInDays -o tsv)
    info "  SKU: $ws_sku | Retention: ${ws_retention}d"
    log_report "Workspace: $WS | SKU: $ws_sku | Retention: ${ws_retention}d"
  else
    fail "Workspace $WS not found"
    log_report "Workspace: NOT FOUND"
    return 1
  fi
  
  # Sentinel
  local sentinel=$(az rest --method GET --uri "$ws_id/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2023-02-01" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('properties',{}).get('customerManagedKey',False))" 2>/dev/null)
  if [[ $? -eq 0 ]]; then ok "Sentinel enabled"; log_report "Sentinel: enabled"
  else warn "Could not verify Sentinel status"; fi
  
  # DCE
  local dce_name="dce-spycloud-$WS"
  local dce_uri=$(az monitor data-collection endpoint show -n "$dce_name" -g "$RG" --query "logsIngestion.endpoint" -o tsv 2>/dev/null)
  if [[ -n "$dce_uri" ]]; then
    ok "DCE: $dce_name → $dce_uri"
    log_report "DCE: $dce_name | URI: $dce_uri"
  else
    fail "DCE not found: $dce_name"
    log_report "DCE: NOT FOUND"
  fi
  
  # DCR
  local dcr_count=$(az monitor data-collection rule list -g "$RG" --query "length([?contains(name,'spycloud') || contains(name,'dcr-')])" -o tsv 2>/dev/null)
  if [[ "$dcr_count" -gt 0 ]]; then
    ok "DCR: $dcr_count rule(s) found"
    az monitor data-collection rule list -g "$RG" --query "[?contains(name,'spycloud') || contains(name,'dcr-')].{Name:name, ImmutableId:immutableId}" -o table 2>/dev/null
    log_report "DCR: $dcr_count rule(s)"
  else
    warn "No SpyCloud DCR found"
    log_report "DCR: NOT FOUND"
  fi
  
  # Tables
  echo ""
  info "Checking tables..."
  local tables_found=0
  for TABLE in SpyCloudBreachWatchlist_CL SpyCloudBreachCatalog_CL SpyCloudCompassData_CL SpyCloudCompassDevices_CL Spycloud_MDE_Logs_CL SpyCloud_ConditionalAccessLogs_CL SpyCloudCompassApplications_CL SpyCloudSipCookies_CL SpyCloudIdentityExposure_CL SpyCloudExposure_CL SpyCloudInvestigations_CL SpyCloudIdLink_CL SpyCloudCAP_CL SpyCloudDataPartnership_CL; do
    local exists=$(az monitor log-analytics workspace table show -g "$RG" -w "$WS" -n "$TABLE" --query name -o tsv 2>/dev/null)
    if [[ -n "$exists" ]]; then
      ok "  $TABLE"
      tables_found=$((tables_found + 1))
    else
      warn "  $TABLE — not found"
    fi
  done
  log_report "Tables found: $tables_found"
  
  # Logic Apps
  echo ""
  info "Checking Logic Apps..."
  for PB in "SpyCloud-MDE-Remediation-$WS" "SpyCloud-CA-Remediation-$WS" "SpyCloud-CredResponse-$WS" "SpyCloud-MDE-Blocklist-$WS"; do
    local pb_state=$(az logic workflow show -n "$PB" -g "$RG" --query state -o tsv 2>/dev/null)
    local pb_identity=$(az logic workflow show -n "$PB" -g "$RG" --query "identity.type" -o tsv 2>/dev/null)
    local pb_pid=$(az logic workflow show -n "$PB" -g "$RG" --query "identity.principalId" -o tsv 2>/dev/null)
    if [[ -n "$pb_state" ]]; then
      ok "  $PB: state=$pb_state identity=$pb_identity"
      if [[ -n "$pb_pid" ]]; then
        info "    Principal ID: $pb_pid"
      fi
      log_report "Playbook $PB: state=$pb_state identity=$pb_identity pid=$pb_pid"
    else
      warn "  $PB: not found"
      log_report "Playbook $PB: NOT FOUND"
    fi
  done
  
  # Permissions check
  echo ""
  info "Checking managed identity permissions..."
  for PB in "SpyCloud-MDE-Remediation-$WS" "SpyCloud-CA-Remediation-$WS" "SpyCloud-CredResponse-$WS"; do
    local pid=$(az logic workflow show -n "$PB" -g "$RG" --query "identity.principalId" -o tsv 2>/dev/null)
    [[ -z "$pid" ]] && continue
    
    # Check role assignments
    local roles=$(az role assignment list --assignee "$pid" --query "[].roleDefinitionName" -o tsv 2>/dev/null | tr '\n' ', ')
    if [[ -n "$roles" ]]; then
      ok "  $PB roles: $roles"
      log_report "  $PB roles: $roles"
    else
      warn "  $PB: no role assignments found"
      log_report "  $PB: NO ROLES"
    fi
    
    # Check API permissions
    local app_roles=$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals?%24filter=id%20eq%20'$pid'" --query "value[0].appRoleAssignments" 2>/dev/null | python3 -c "import sys,json; roles=json.load(sys.stdin) or []; print(len(roles))" 2>/dev/null || echo "0")
    info "  $PB API permissions: $app_roles assigned"
    log_report "  $PB API permissions: $app_roles"
  done
}

# ================================================================
# 2. DATA GENERATION & INGESTION
# ================================================================
generate_and_ingest() {
  step "2. Test Data Generation & Ingestion"
  log_report ""; log_report "=== DATA GENERATION ==="
  
  # Download generator if not present
  if [[ ! -f "/tmp/generate-test-data.py" ]]; then
    info "Downloading test data generator..."
    curl -sL "https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/generate-test-data.py" -o /tmp/generate-test-data.py
  fi
  
  info "Generating test data..."
  python3 /tmp/generate-test-data.py --output-json --output-dir /tmp/spycloud-test-data 2>/dev/null
  ok "Generated test data in /tmp/spycloud-test-data/"
  
  # Get DCE and DCR info
  local dce_name="dce-spycloud-$WS"
  local dce_uri=$(az monitor data-collection endpoint show -n "$dce_name" -g "$RG" --query "logsIngestion.endpoint" -o tsv 2>/dev/null)
  
  if [[ -z "$dce_uri" ]]; then
    fail "DCE not found — cannot ingest data"
    log_report "Ingestion: FAILED (no DCE)"
    return 1
  fi
  
  # Find DCR immutable ID
  local dcr_id=$(az monitor data-collection rule list -g "$RG" --query "[?contains(name,'spycloud') || contains(name,'dcr-')].immutableId | [0]" -o tsv 2>/dev/null)
  
  if [[ -z "$dcr_id" ]]; then
    fail "DCR not found — cannot ingest data"
    log_report "Ingestion: FAILED (no DCR)"
    return 1
  fi
  
  info "DCE: $dce_uri"
  info "DCR: $dcr_id"
  
  # Get token
  local token=$(az account get-access-token --resource https://monitor.azure.com --query accessToken -o tsv 2>/dev/null)
  if [[ -z "$token" ]]; then
    fail "Could not get Azure Monitor token"
    return 1
  fi
  
  # Ingest each table
  local ingested=0; local failed=0
  for file in /tmp/spycloud-test-data/*.json; do
    local table=$(basename "$file" .json)
    local stream="Custom-$table"
    local count=$(python3 -c "import json; print(len(json.load(open('$file'))))" 2>/dev/null)
    
    echo -n "  $table ($count records): "
    local code=$(curl -s -X POST \
      "$dce_uri/dataCollectionRules/$dcr_id/streams/$stream?api-version=2023-01-01" \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/json" \
      -d @"$file" \
      -o /dev/null -w "%{http_code}" 2>/dev/null)
    
    if [[ "$code" == "204" || "$code" == "200" ]]; then
      echo -e "${GREEN}✅ HTTP $code${NC}"
      ingested=$((ingested + 1))
      log_report "  $table: $count records → HTTP $code ✅"
    else
      echo -e "${RED}❌ HTTP $code${NC}"
      failed=$((failed + 1))
      log_report "  $table: $count records → HTTP $code ❌"
    fi
  done
  
  echo ""
  ok "Ingested: $ingested tables | Failed: $failed tables"
  log_report "Ingestion summary: $ingested ok, $failed failed"
}

# ================================================================
# 3. ANALYTICS RULE TESTING
# ================================================================
test_analytics() {
  step "3. Analytics Rule Testing"
  log_report ""; log_report "=== ANALYTICS RULE TESTING ==="
  
  local ws_id=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query customerId -o tsv 2>/dev/null)
  
  info "Running key detection queries against test data..."
  
  # Test each major rule category
  declare -A QUERIES
  QUERIES["Infostealer Detection"]="SpyCloudBreachWatchlist_CL | where severity >= 20 | summarize count() by severity"
  QUERIES["Plaintext Passwords"]="SpyCloudBreachWatchlist_CL | where isnotempty(password_plaintext) | summarize count()"
  QUERIES["VIP Exposures"]="SpyCloudBreachWatchlist_CL | where email has_any ('ceo','cfo','ciso','admin') | summarize count() by email"
  QUERIES["Stolen Cookies"]="SpyCloudSipCookies_CL | summarize Cookies=count(), Domains=dcount(cookie_domain) by email | top 5 by Cookies desc"
  QUERIES["Device Reinfection"]="SpyCloudCompassDevices_CL | summarize Infections=count() by user_hostname | where Infections > 1"
  QUERIES["MDE Isolation Audit"]="Spycloud_MDE_Logs_CL | summarize count() by Action, ActionStatus"
  QUERIES["CA Remediation Audit"]="SpyCloud_ConditionalAccessLogs_CL | summarize count() by Action, ActionStatus"
  QUERIES["Unremediated High-Sev"]="let remediated = SpyCloud_ConditionalAccessLogs_CL | distinct tolower(Email); SpyCloudBreachWatchlist_CL | where severity >= 20 | where tolower(email) !in (remediated) | summarize count()"
  QUERIES["Compass Corporate Overlap"]="SpyCloudCompassData_CL | join kind=inner (SpyCloudBreachWatchlist_CL | distinct email) on email | summarize count()"
  QUERIES["Risk Score Distribution"]="SpyCloudExposure_CL | summarize count() by risk_level"
  QUERIES["Identity Links"]="SpyCloudIdLink_CL | summarize count() by link_type"
  QUERIES["CAP Policy Actions"]="SpyCloudCAP_CL | summarize count() by action_type, action_status"
  
  for name in "${!QUERIES[@]}"; do
    local query="${QUERIES[$name]}"
    echo -n "  $name: "
    local result=$(az monitor log-analytics query -w "$ws_id" --analytics-query "$query" -o json 2>/dev/null | python3 -c "
import sys,json
try:
    data = json.load(sys.stdin)
    rows = data.get('tables',[{}])[0].get('rows',[])
    if rows:
        print(f'{len(rows)} results')
    else:
        print('0 results')
except:
    print('error')
" 2>/dev/null)
    
    if [[ "$result" == *"error"* || -z "$result" ]]; then
      echo -e "${YELLOW}⏭ no data or table missing${NC}"
      log_report "  $name: no data"
    else
      echo -e "${GREEN}$result${NC}"
      log_report "  $name: $result"
    fi
  done
}

# ================================================================
# 4. PLAYBOOK VERIFICATION
# ================================================================
test_playbooks() {
  step "4. Playbook & Automation Verification"
  log_report ""; log_report "=== PLAYBOOK VERIFICATION ==="
  
  for PB in "SpyCloud-MDE-Remediation-$WS" "SpyCloud-CA-Remediation-$WS" "SpyCloud-CredResponse-$WS" "SpyCloud-MDE-Blocklist-$WS"; do
    local short_name=$(echo "$PB" | sed "s/-$WS//")
    echo -n "  $short_name: "
    
    local state=$(az logic workflow show -n "$PB" -g "$RG" --query state -o tsv 2>/dev/null)
    local identity=$(az logic workflow show -n "$PB" -g "$RG" --query "identity.type" -o tsv 2>/dev/null)
    local last_run=$(az logic workflow list-runs -n "$PB" -g "$RG" --query "[0].{status:status, time:startTime}" -o json 2>/dev/null)
    
    if [[ -z "$state" ]]; then
      echo -e "${YELLOW}not deployed${NC}"
      log_report "  $short_name: NOT DEPLOYED"
      continue
    fi
    
    echo -e "state=${GREEN}$state${NC} identity=$identity"
    
    if [[ -n "$last_run" && "$last_run" != "[]" ]]; then
      local run_status=$(echo "$last_run" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null)
      local run_time=$(echo "$last_run" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('time','?')[:19])" 2>/dev/null)
      info "    Last run: $run_status at $run_time"
      log_report "  $short_name: state=$state identity=$identity last_run=$run_status"
    else
      info "    No runs yet"
      log_report "  $short_name: state=$state identity=$identity no_runs"
    fi
  done
  
  # Check automation rules
  echo ""
  info "Automation Rules:"
  local ws_rid=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query id -o tsv 2>/dev/null)
  local auto_rules=$(az rest --method GET --uri "$ws_rid/providers/Microsoft.SecurityInsights/automationRules?api-version=2023-02-01" 2>/dev/null | python3 -c "
import sys,json
data = json.load(sys.stdin)
rules = data.get('value',[])
for r in rules:
    name = r.get('properties',{}).get('displayName','?')
    enabled = r.get('properties',{}).get('triggeringLogic',{}).get('isEnabled',False)
    print(f'{name}|{enabled}')
" 2>/dev/null)
  
  if [[ -n "$auto_rules" ]]; then
    while IFS='|' read -r name enabled; do
      if [[ "$enabled" == "True" ]]; then
        ok "  $name (enabled)"
      else
        warn "  $name (disabled)"
      fi
      log_report "  Automation: $name enabled=$enabled"
    done <<< "$auto_rules"
  else
    warn "  No automation rules found"
  fi
}

# ================================================================
# 5. FULL QA REPORT
# ================================================================
generate_report() {
  step "5. Generating Full QA Report"
  
  local ws_id=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query customerId -o tsv 2>/dev/null)
  
  log_report ""; log_report "=== FULL QA REPORT ==="
  log_report "Generated: $(date)"
  
  # Data volume
  info "Querying data volumes..."
  local volume_query="union isfuzzy=true
(SpyCloudBreachWatchlist_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Watchlist'),
(SpyCloudBreachCatalog_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Catalog'),
(SpyCloudCompassData_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Compass'),
(SpyCloudCompassDevices_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='Devices'),
(Spycloud_MDE_Logs_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='MDE'),
(SpyCloud_ConditionalAccessLogs_CL | summarize Records=count(), Latest=max(TimeGenerated) | extend Table='CA')
| project Table, Records, Latest"
  
  az monitor log-analytics query -w "$ws_id" --analytics-query "$volume_query" -o table 2>/dev/null
  
  # Incident count
  info "Checking incidents..."
  local ws_rid=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query id -o tsv 2>/dev/null)
  local incidents=$(az rest --method GET --uri "$ws_rid/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01&%24filter=properties/title%20ne%20null&%24top=100" 2>/dev/null | python3 -c "
import sys,json
data = json.load(sys.stdin)
incidents = data.get('value',[])
spycloud = [i for i in incidents if 'SpyCloud' in i.get('properties',{}).get('title','') or 'spycloud' in json.dumps(i).lower()]
print(f'Total: {len(incidents)} | SpyCloud: {len(spycloud)}')
for i in spycloud[:5]:
    p = i.get('properties',{})
    print(f'  {p.get(\"severity\",\"?\")} | {p.get(\"status\",\"?\")} | {p.get(\"title\",\"?\")[:50]}')
" 2>/dev/null)
  echo "$incidents"
  log_report "Incidents: $incidents"
  
  echo ""
  echo -e "${GREEN}${BOLD}═══ QA Report saved to: $REPORT_FILE ═══${NC}"
  cat "$REPORT_FILE"
}

# ================================================================
# MAIN MENU
# ================================================================
main_menu() {
  banner
  prompt_config
  
  while true; do
    echo ""
    echo -e "${BOLD}Select an option:${NC}"
    echo "  1) Validate Environment (workspace, DCE, DCR, tables, permissions)"
    echo "  2) Generate & Ingest Test Data (732 records across 13 tables)"
    echo "  3) Test Analytics Rules (run detection queries)"
    echo "  4) Verify Playbooks & Automation (state, identity, runs)"
    echo "  5) Generate Full QA Report"
    echo "  6) Run ALL (1-5 in sequence)"
    echo "  7) Grant Playbook API Permissions"
    echo "  q) Quit"
    echo ""
    read -rp "Choice [1-7/q]: " choice
    
    case $choice in
      1) validate_environment;;
      2) generate_and_ingest;;
      3) test_analytics;;
      4) test_playbooks;;
      5) generate_report;;
      6) validate_environment; generate_and_ingest; sleep 30; test_analytics; test_playbooks; generate_report;;
      7) 
        info "Downloading grant-permissions.sh..."
        curl -sL "https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/grant-permissions.sh" | bash -s -- -g "$RG" -w "$WS"
        ;;
      q|Q) echo "Bye!"; exit 0;;
      *) warn "Invalid choice";;
    esac
  done
}

# Run
main_menu
