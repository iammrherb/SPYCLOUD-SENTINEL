#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# SpyCloud Sentinel — Resource Audit & Health Check
# Audits all deployed Azure resources, validates connectivity, and
# reports on the operational status of the SpyCloud Sentinel integration.
#
# Usage: ./audit-resources.sh -g <resource-group> -w <workspace> [-s <subscription-id>]
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Color codes ──────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Counters ─────────────────────────────────────────────────────────
PASS=0
WARN=0
FAIL=0
SKIP=0

# ── Parameters ───────────────────────────────────────────────────────
RG=""
WS=""
SUB=""
SPYCLOUD_API_KEY="${SPYCLOUD_API_KEY:-}"
VERBOSE=false
OUTPUT_FILE=""

usage() {
    echo ""
    echo "SpyCloud Sentinel — Resource Audit"
    echo ""
    echo "Usage: $0 -g <resource-group> -w <workspace> [options]"
    echo ""
    echo "Required:"
    echo "  -g    Azure resource group name"
    echo "  -w    Log Analytics workspace name"
    echo ""
    echo "Optional:"
    echo "  -s    Azure subscription ID (default: current subscription)"
    echo "  -k    SpyCloud API key (or set SPYCLOUD_API_KEY env var)"
    echo "  -o    Write report to file (in addition to stdout)"
    echo "  -v    Verbose output"
    echo "  -h    Show this help"
    echo ""
    exit 1
}

while getopts "g:w:s:k:o:vh" opt; do
    case $opt in
        g) RG="$OPTARG" ;;
        w) WS="$OPTARG" ;;
        s) SUB="$OPTARG" ;;
        k) SPYCLOUD_API_KEY="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        v) VERBOSE=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

[ -z "$RG" ] || [ -z "$WS" ] && usage

# ── Output helpers ───────────────────────────────────────────────────
_log() {
    local msg="$1"
    echo -e "$msg"
    if [ -n "$OUTPUT_FILE" ]; then
        echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_FILE"
    fi
}

pass() {
    ((PASS++))
    _log "  ${GREEN}[PASS]${NC}  $1"
}

warn() {
    ((WARN++))
    _log "  ${YELLOW}[WARN]${NC}  $1"
}

fail() {
    ((FAIL++))
    _log "  ${RED}[FAIL]${NC}  $1"
}

skip() {
    ((SKIP++))
    _log "  ${DIM}[SKIP]${NC}  $1"
}

info() {
    _log "  ${BLUE}[INFO]${NC}  $1"
}

section() {
    _log ""
    _log "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    _log "${CYAN}  $1${NC}"
    _log "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ── Prerequisite checks ──────────────────────────────────────────────
if ! command -v az &>/dev/null; then
    echo -e "${RED}Error: Azure CLI (az) is not installed or not in PATH.${NC}"
    exit 1
fi

if ! az account show &>/dev/null; then
    echo -e "${RED}Error: Not logged in to Azure CLI. Run 'az login' first.${NC}"
    exit 1
fi

# ── Initialize ───────────────────────────────────────────────────────
if [ -n "$OUTPUT_FILE" ]; then
    > "$OUTPUT_FILE"
fi

if [ -n "$SUB" ]; then
    az account set --subscription "$SUB" 2>/dev/null || {
        echo -e "${RED}Error: Could not set subscription $SUB${NC}"
        exit 1
    }
fi

SUB_ID=$(az account show --query id -o tsv 2>/dev/null)
SUB_NAME=$(az account show --query name -o tsv 2>/dev/null)
TENANT_ID=$(az account show --query tenantId -o tsv 2>/dev/null)

# ── Header ───────────────────────────────────────────────────────────
_log ""
_log "${MAGENTA}╔══════════════════════════════════════════════════════════════════╗${NC}"
_log "${MAGENTA}║       SpyCloud Sentinel — Resource Audit & Health Check         ║${NC}"
_log "${MAGENTA}╚══════════════════════════════════════════════════════════════════╝${NC}"
_log ""
_log "  Subscription : ${BOLD}$SUB_NAME${NC} ($SUB_ID)"
_log "  Tenant       : $TENANT_ID"
_log "  Resource Group: ${BOLD}$RG${NC}"
_log "  Workspace    : ${BOLD}$WS${NC}"
_log "  Timestamp    : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# ══════════════════════════════════════════════════════════════════════
# Section 1: Resource Group & Workspace
# ══════════════════════════════════════════════════════════════════════
section "1. Resource Group & Log Analytics Workspace"

# Check resource group exists
if az group show --name "$RG" &>/dev/null; then
    RG_LOCATION=$(az group show --name "$RG" --query location -o tsv 2>/dev/null)
    pass "Resource group '$RG' exists (location: $RG_LOCATION)"
else
    fail "Resource group '$RG' not found"
    _log ""
    _log "${RED}Cannot continue without a valid resource group. Exiting.${NC}"
    exit 1
fi

# Check workspace exists
WS_ID=$(az monitor log-analytics workspace show \
    --resource-group "$RG" --workspace-name "$WS" \
    --query customerId -o tsv 2>/dev/null) || WS_ID=""

if [ -n "$WS_ID" ]; then
    WS_SKU=$(az monitor log-analytics workspace show \
        --resource-group "$RG" --workspace-name "$WS" \
        --query sku.name -o tsv 2>/dev/null)
    WS_RETENTION=$(az monitor log-analytics workspace show \
        --resource-group "$RG" --workspace-name "$WS" \
        --query retentionInDays -o tsv 2>/dev/null)
    pass "Workspace '$WS' exists (ID: $WS_ID)"
    info "SKU: $WS_SKU | Retention: ${WS_RETENTION} days"
else
    fail "Workspace '$WS' not found in resource group '$RG'"
    _log ""
    _log "${RED}Cannot continue without a valid workspace. Exiting.${NC}"
    exit 1
fi

# Check Sentinel is enabled
SENTINEL_ENABLED=$(az monitor log-analytics workspace show \
    --resource-group "$RG" --workspace-name "$WS" \
    --query "features.enableLogAccessUsingOnlyResourcePermissions" -o tsv 2>/dev/null)

SENTINEL_SOLUTION=$(az monitor log-analytics solution list \
    --resource-group "$RG" \
    --query "[?contains(name, 'SecurityInsights')].name" -o tsv 2>/dev/null) || SENTINEL_SOLUTION=""

if [ -n "$SENTINEL_SOLUTION" ]; then
    pass "Microsoft Sentinel is enabled on workspace"
else
    warn "Microsoft Sentinel solution not detected (may require manual verification)"
fi

# ══════════════════════════════════════════════════════════════════════
# Section 2: Data Collection Resources (DCE, DCR)
# ══════════════════════════════════════════════════════════════════════
section "2. Data Collection Endpoint & Rule"

# Data Collection Endpoints
DCE_LIST=$(az monitor data-collection endpoint list \
    --resource-group "$RG" \
    --query "[?contains(name, 'spycloud')].{name:name, state:provisioningState}" \
    -o json 2>/dev/null) || DCE_LIST="[]"

DCE_COUNT=$(echo "$DCE_LIST" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

if [ "$DCE_COUNT" -gt 0 ]; then
    pass "Found $DCE_COUNT SpyCloud Data Collection Endpoint(s)"
    echo "$DCE_LIST" | python3 -c "
import sys, json
for dce in json.load(sys.stdin):
    state = dce.get('state', 'Unknown')
    marker = '\033[0;32m[OK]\033[0m' if state == 'Succeeded' else '\033[0;31m[!!]\033[0m'
    print(f'           {marker} {dce[\"name\"]} (state: {state})')
" 2>/dev/null
else
    fail "No SpyCloud Data Collection Endpoint found"
fi

# Data Collection Rules
DCR_LIST=$(az monitor data-collection rule list \
    --resource-group "$RG" \
    --query "[?contains(name, 'spycloud')].{name:name, state:provisioningState}" \
    -o json 2>/dev/null) || DCR_LIST="[]"

DCR_COUNT=$(echo "$DCR_LIST" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

if [ "$DCR_COUNT" -gt 0 ]; then
    pass "Found $DCR_COUNT SpyCloud Data Collection Rule(s)"
    echo "$DCR_LIST" | python3 -c "
import sys, json
for dcr in json.load(sys.stdin):
    state = dcr.get('state', 'Unknown')
    marker = '\033[0;32m[OK]\033[0m' if state == 'Succeeded' else '\033[0;31m[!!]\033[0m'
    print(f'           {marker} {dcr[\"name\"]} (state: {state})')
" 2>/dev/null
else
    fail "No SpyCloud Data Collection Rule found"
fi

# ══════════════════════════════════════════════════════════════════════
# Section 3: Custom Tables
# ══════════════════════════════════════════════════════════════════════
section "3. Custom Log Tables"

EXPECTED_TABLES=(
    "SpyCloudBreachWatchlist_CL"
    "SpyCloudBreachCatalog_CL"
    "SpyCloudMDEEnrichment_CL"
    "SpyCloudConditionalAccess_CL"
    "SpyCloudCompassDevices_CL"
    "SpyCloudCompassApplications_CL"
)

TABLE_FOUND=0
TABLE_MISSING=0

for TABLE in "${EXPECTED_TABLES[@]}"; do
    TABLE_EXISTS=$(az monitor log-analytics workspace table show \
        --resource-group "$RG" --workspace-name "$WS" \
        --name "$TABLE" --query name -o tsv 2>/dev/null) || TABLE_EXISTS=""

    if [ -n "$TABLE_EXISTS" ]; then
        ((TABLE_FOUND++))
        # Check for recent data
        LAST_RECORD=$(az monitor log-analytics query \
            --workspace "$WS_ID" \
            --analytics-query "${TABLE} | summarize max(TimeGenerated) | project LastRecord=max_TimeGenerated" \
            --timespan "P30D" \
            --query "[0].LastRecord" -o tsv 2>/dev/null) || LAST_RECORD=""

        if [ -n "$LAST_RECORD" ] && [ "$LAST_RECORD" != "null" ] && [ "$LAST_RECORD" != "" ]; then
            pass "$TABLE (last record: $LAST_RECORD)"
        else
            warn "$TABLE exists but no data in last 30 days"
        fi
    else
        ((TABLE_MISSING++))
        fail "$TABLE not found"
    fi
done

info "Tables: $TABLE_FOUND found, $TABLE_MISSING missing out of ${#EXPECTED_TABLES[@]} expected"

# ══════════════════════════════════════════════════════════════════════
# Section 4: Function App
# ══════════════════════════════════════════════════════════════════════
section "4. Function App (Data Connector)"

FUNC_APPS=$(az functionapp list \
    --resource-group "$RG" \
    --query "[?contains(name, 'spycloud') || contains(name, 'SpyCloud')].{name:name, state:state, defaultHostName:defaultHostName}" \
    -o json 2>/dev/null) || FUNC_APPS="[]"

FUNC_COUNT=$(echo "$FUNC_APPS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

if [ "$FUNC_COUNT" -gt 0 ]; then
    echo "$FUNC_APPS" | python3 -c "
import sys, json
apps = json.load(sys.stdin)
for app in apps:
    state = app.get('state', 'Unknown')
    if state == 'Running':
        print(f'  \033[0;32m[PASS]\033[0m  {app[\"name\"]} \u2014 Running ({app.get(\"defaultHostName\", \"\")})')
    else:
        print(f'  \033[0;31m[FAIL]\033[0m  {app[\"name\"]} \u2014 {state}')
" 2>/dev/null
else
    # Also try without name filter
    ALL_FUNCS=$(az functionapp list --resource-group "$RG" --query "[].name" -o tsv 2>/dev/null) || ALL_FUNCS=""
    if [ -n "$ALL_FUNCS" ]; then
        warn "No Function App with 'spycloud' in the name. Found: $ALL_FUNCS"
    else
        fail "No Function App found in resource group"
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# Section 5: SpyCloud API Connectivity
# ══════════════════════════════════════════════════════════════════════
section "5. SpyCloud API Connectivity"

if [ -n "$SPYCLOUD_API_KEY" ]; then
    API_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $SPYCLOUD_API_KEY" \
        -H "Content-Type: application/json" \
        --max-time 15 \
        "https://api.spycloud.io/enterprise-v2/breach/catalog?limit=1" 2>/dev/null) || API_RESPONSE="000"

    case "$API_RESPONSE" in
        200) pass "SpyCloud API reachable (HTTP 200)" ;;
        401) fail "SpyCloud API returned 401 Unauthorized \u2014 check API key" ;;
        403) fail "SpyCloud API returned 403 Forbidden \u2014 API key lacks required scope" ;;
        429) warn "SpyCloud API returned 429 Rate Limited \u2014 try again later" ;;
        000) fail "SpyCloud API unreachable \u2014 network timeout or DNS failure" ;;
        *)   warn "SpyCloud API returned HTTP $API_RESPONSE" ;;
    esac

    # Test breach data endpoint
    BREACH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $SPYCLOUD_API_KEY" \
        --max-time 15 \
        "https://api.spycloud.io/enterprise-v2/breach/data/watchlist?limit=1" 2>/dev/null) || BREACH_RESPONSE="000"

    if [ "$BREACH_RESPONSE" = "200" ]; then
        pass "SpyCloud Watchlist endpoint reachable"
    else
        warn "SpyCloud Watchlist endpoint returned HTTP $BREACH_RESPONSE"
    fi
else
    skip "SpyCloud API key not provided (use -k flag or SPYCLOUD_API_KEY env var)"
fi

# ══════════════════════════════════════════════════════════════════════
# Section 6: Analytics Rules
# ══════════════════════════════════════════════════════════════════════
section "6. Analytics Rules"

RULES_JSON=$(az rest \
    --method get \
    --url "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01" \
    2>/dev/null) || RULES_JSON=""

if [ -n "$RULES_JSON" ]; then
    echo "$RULES_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data.get('value', [])
spycloud_rules = [r for r in rules if 'spycloud' in json.dumps(r).lower()]
total = len(spycloud_rules)
enabled = sum(1 for r in spycloud_rules if r.get('properties', {}).get('enabled', False))
disabled = total - enabled

if total > 0:
    print(f'  \033[0;32m[PASS]\033[0m  {total} SpyCloud analytics rules found')
    print(f'           Enabled: {enabled} | Disabled: {disabled}')
    if disabled > 0:
        for r in spycloud_rules:
            if not r.get('properties', {}).get('enabled', False):
                name = r.get('properties', {}).get('displayName', r.get('name', 'Unknown'))
                print(f'           \033[1;33m[OFF]\033[0m {name}')
else:
    print(f'  \033[1;33m[WARN]\033[0m  No SpyCloud-specific analytics rules found (checked {len(rules)} total rules)')
" 2>/dev/null
else
    warn "Could not query analytics rules (check permissions: Microsoft.SecurityInsights/alertRules/read)"
fi

# ══════════════════════════════════════════════════════════════════════
# Section 7: Playbooks (Logic Apps)
# ══════════════════════════════════════════════════════════════════════
section "7. Playbooks (Logic Apps)"

PLAYBOOKS=$(az logic workflow list \
    --resource-group "$RG" \
    --query "[?contains(name, 'SpyCloud') || contains(name, 'spycloud')].{name:name, state:state, changedTime:changedTime}" \
    -o json 2>/dev/null) || PLAYBOOKS="[]"

PB_COUNT=$(echo "$PLAYBOOKS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

if [ "$PB_COUNT" -gt 0 ]; then
    pass "Found $PB_COUNT SpyCloud playbook(s)"
    echo "$PLAYBOOKS" | python3 -c "
import sys, json
from datetime import datetime
playbooks = json.load(sys.stdin)
for pb in sorted(playbooks, key=lambda x: x['name']):
    state = pb.get('state', 'Unknown')
    changed = pb.get('changedTime', '')[:19]
    if state == 'Enabled':
        marker = '\033[0;32m[ON] \033[0m'
    else:
        marker = '\033[0;31m[OFF]\033[0m'
    print(f'           {marker} {pb[\"name\"]}  (last modified: {changed})')
" 2>/dev/null

    # Check recent playbook runs
    for PB_NAME in $(echo "$PLAYBOOKS" | python3 -c "import sys,json; [print(p['name']) for p in json.load(sys.stdin)]" 2>/dev/null); do
        LAST_RUN=$(az logic workflow list-run \
            --resource-group "$RG" --workflow-name "$PB_NAME" \
            --top 1 --query "[0].{status:status, startTime:startTime}" -o json 2>/dev/null) || LAST_RUN=""

        if [ -n "$LAST_RUN" ] && [ "$LAST_RUN" != "[]" ] && [ "$LAST_RUN" != "null" ]; then
            echo "$LAST_RUN" | python3 -c "
import sys, json
run = json.load(sys.stdin)
status = run.get('status', 'Unknown')
start = run.get('startTime', '')[:19]
name = '$PB_NAME'
if status == 'Succeeded':
    print(f'           \033[2m  Last run: {start} \u2014 {status}\033[0m')
elif status == 'Failed':
    print(f'           \033[0;31m  Last run: {start} \u2014 FAILED\033[0m')
else:
    print(f'           \033[2m  Last run: {start} \u2014 {status}\033[0m')
" 2>/dev/null
        fi
    done
else
    warn "No SpyCloud playbooks found in resource group"
fi

# ══════════════════════════════════════════════════════════════════════
# Section 8: Workbooks
# ══════════════════════════════════════════════════════════════════════
section "8. Workbooks"

WORKBOOKS=$(az rest \
    --method get \
    --url "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Insights/workbooks?api-version=2023-06-01&canFetchContent=false" \
    2>/dev/null) || WORKBOOKS=""

if [ -n "$WORKBOOKS" ]; then
    echo "$WORKBOOKS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
books = data.get('value', [])
spycloud_books = [b for b in books if 'spycloud' in json.dumps(b).lower()]
if spycloud_books:
    print(f'  \033[0;32m[PASS]\033[0m  {len(spycloud_books)} SpyCloud workbook(s) found')
    for wb in spycloud_books:
        name = wb.get('properties', {}).get('displayName', wb.get('name', 'Unknown'))
        modified = wb.get('properties', {}).get('timeModified', '')[:19]
        print(f'           \033[0;32m[OK]\033[0m {name}  (modified: {modified})')
else:
    print(f'  \033[1;33m[WARN]\033[0m  No SpyCloud workbooks found ({len(books)} total workbooks in resource group)')
" 2>/dev/null
else
    warn "Could not query workbooks (check permissions: Microsoft.Insights/workbooks/read)"
fi

# ══════════════════════════════════════════════════════════════════════
# Section 9: Data Ingestion Health
# ══════════════════════════════════════════════════════════════════════
section "9. Data Ingestion Health"

INGESTION_QUERY="SpyCloudBreachWatchlist_CL
| summarize
    TotalRecords = count(),
    LastIngestion = max(TimeGenerated),
    First24h = countif(TimeGenerated > ago(24h)),
    First7d = countif(TimeGenerated > ago(7d))
| extend HoursSinceLastIngestion = datetime_diff('hour', now(), LastIngestion)"

INGESTION=$(az monitor log-analytics query \
    --workspace "$WS_ID" \
    --analytics-query "$INGESTION_QUERY" \
    --timespan "P30D" \
    -o json 2>/dev/null) || INGESTION=""

if [ -n "$INGESTION" ] && [ "$INGESTION" != "[]" ]; then
    echo "$INGESTION" | python3 -c "
import sys, json
rows = json.load(sys.stdin)
if rows:
    r = rows[0]
    total = int(r.get('TotalRecords', 0))
    last = r.get('LastIngestion', 'N/A')
    last_24h = int(r.get('First24h', 0))
    last_7d = int(r.get('First7d', 0))
    hours_since = int(r.get('HoursSinceLastIngestion', 999))

    if hours_since <= 24:
        print(f'  \033[0;32m[PASS]\033[0m  Data ingestion active \u2014 last record {hours_since}h ago')
    elif hours_since <= 72:
        print(f'  \033[1;33m[WARN]\033[0m  Data ingestion stale \u2014 last record {hours_since}h ago')
    else:
        print(f'  \033[0;31m[FAIL]\033[0m  Data ingestion stopped \u2014 last record {hours_since}h ago')

    print(f'           Total records (30d): {total:,}')
    print(f'           Last 24 hours:       {last_24h:,}')
    print(f'           Last 7 days:         {last_7d:,}')
    print(f'           Last ingestion:      {last}')
else:
    print('  \033[0;31m[FAIL]\033[0m  No data in SpyCloudBreachWatchlist_CL (last 30 days)')
" 2>/dev/null
else
    fail "Could not query ingestion health (table may not exist or no permissions)"
fi

# ══════════════════════════════════════════════════════════════════════
# Section 10: Watchlists
# ══════════════════════════════════════════════════════════════════════
section "10. Sentinel Watchlists"

WATCHLISTS=$(az rest \
    --method get \
    --url "https://management.azure.com/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS/providers/Microsoft.SecurityInsights/watchlists?api-version=2024-03-01" \
    2>/dev/null) || WATCHLISTS=""

if [ -n "$WATCHLISTS" ]; then
    echo "$WATCHLISTS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
lists = data.get('value', [])
spycloud_lists = [w for w in lists if 'spycloud' in json.dumps(w).lower()]
if spycloud_lists:
    print(f'  \033[0;32m[PASS]\033[0m  {len(spycloud_lists)} SpyCloud watchlist(s) found')
    for wl in spycloud_lists:
        name = wl.get('properties', {}).get('displayName', wl.get('name', 'Unknown'))
        alias = wl.get('properties', {}).get('watchlistAlias', '')
        items = wl.get('properties', {}).get('numberOfLinksCount', 'N/A')
        print(f'           \033[0;32m[OK]\033[0m {name} (alias: {alias}, items: {items})')
else:
    print(f'  \033[1;33m[WARN]\033[0m  No SpyCloud watchlists found ({len(lists)} total)')
" 2>/dev/null
else
    warn "Could not query watchlists"
fi

# ══════════════════════════════════════════════════════════════════════
# Summary Report
# ══════════════════════════════════════════════════════════════════════
_log ""
_log "${MAGENTA}══════════════════════════════════════════════════════════════════${NC}"
_log "${MAGENTA}  AUDIT SUMMARY${NC}"
_log "${MAGENTA}══════════════════════════════════════════════════════════════════${NC}"
_log ""
_log "  ${GREEN}PASS : $PASS${NC}"
_log "  ${YELLOW}WARN : $WARN${NC}"
_log "  ${RED}FAIL : $FAIL${NC}"
_log "  ${DIM}SKIP : $SKIP${NC}"
_log ""

TOTAL=$((PASS + WARN + FAIL + SKIP))
if [ "$TOTAL" -eq 0 ]; then
    _log "  No checks were executed."
elif [ "$FAIL" -eq 0 ] && [ "$WARN" -eq 0 ]; then
    _log "  ${GREEN}${BOLD}All checks passed. SpyCloud Sentinel deployment is healthy.${NC}"
elif [ "$FAIL" -eq 0 ]; then
    _log "  ${YELLOW}${BOLD}Deployment is operational with $WARN warning(s). Review items above.${NC}"
else
    _log "  ${RED}${BOLD}$FAIL check(s) failed. Remediation required. Review items above.${NC}"
fi

_log ""
_log "  Audit completed at $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

if [ -n "$OUTPUT_FILE" ]; then
    _log "  Report saved to: $OUTPUT_FILE"
fi

_log ""

# Exit with appropriate code
if [ "$FAIL" -gt 0 ]; then
    exit 2
elif [ "$WARN" -gt 0 ]; then
    exit 1
else
    exit 0
fi
