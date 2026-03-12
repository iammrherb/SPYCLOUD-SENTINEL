#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#  SpyCloud Sentinel — Test Data Deployment Orchestrator
#  Version: 1.0.0
#
#  Orchestrates synthetic test data generation, ingestion into Log Analytics,
#  validation, and sample analytic rule testing for the SpyCloud Sentinel
#  deployment.
#
#  Prerequisites:
#    - Azure CLI (az) authenticated
#    - Python 3.8+ with standard library
#    - Log Analytics workspace with SpyCloud tables deployed
#    - 'requests' Python package (for Sentinel ingestion)
#
#  Usage:
#    # Full pipeline: generate -> ingest -> validate -> test
#    ./scripts/deploy-test-data.sh -g <resource-group> -w <workspace> --count 25
#
#    # Generate files only (no Azure connection needed)
#    ./scripts/deploy-test-data.sh --generate-only --count 50
#
#    # Run purple team scenario and ingest
#    ./scripts/deploy-test-data.sh -g <rg> -w <ws> --scenario infostealer-outbreak
#
#    # Skip validation (useful in CI)
#    ./scripts/deploy-test-data.sh -g <rg> -w <ws> --skip-validation
#═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

T0=$(date +%s)
elapsed(){ printf "%dm%02ds" $(( ($(date +%s)-T0)/60 )) $(( ($(date +%s)-T0)%60 )); }

# ─── Logging ──────────────────────────────────────────────────────────────────
LOGFILE="/tmp/spycloud-test-data-$(date +%Y%m%d-%H%M%S).log"

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
step() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} ${BOLD}$1${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ─── Banner ───────────────────────────────────────────────────────────────────
show_banner() {
cat << 'BANNER'

   ╔═══════════════════════════════════════════════════════════════╗
   ║  SpyCloud Sentinel — Test Data Deployment Orchestrator       ║
   ║  Generate, ingest, validate, and test synthetic SpyCloud     ║
   ║  data across all custom Log Analytics tables.                ║
   ╚═══════════════════════════════════════════════════════════════╝

BANNER
}

# ─── Defaults ─────────────────────────────────────────────────────────────────
RESOURCE_GROUP=""
WORKSPACE=""
RECORD_COUNT=20
SCENARIO=""
PURPLE_SCENARIO=""
GENERATE_ONLY=false
SKIP_VALIDATION=false
SKIP_ANALYTICS=false
OUTPUT_DIR="./spycloud-test-data"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAIT_MINUTES=10

# SpyCloud custom tables to validate
SPYCLOUD_TABLES=(
    "SpyCloudBreachWatchlist_CL"
    "SpyCloudBreachCatalog_CL"
    "SpyCloudCompassData_CL"
    "SpyCloudCompassDevices_CL"
    "SpyCloudCompassApplications_CL"
    "SpyCloudSipCookies_CL"
    "SpyCloudIdentityExposure_CL"
    "SpyCloudInvestigations_CL"
    "SpyCloudIdLink_CL"
    "SpyCloudExposure_CL"
    "SpyCloudCAP_CL"
    "SpyCloudDataPartnership_CL"
    "Spycloud_MDE_Logs_CL"
    "SpyCloud_ConditionalAccessLogs_CL"
)

# ─── Argument parsing ────────────────────────────────────────────────────────
usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  -g, --resource-group RG    Azure resource group containing the workspace
  -w, --workspace WS         Log Analytics workspace name
  --count N                  Records per table (default: 20)
  --scenario NAME            Simulation scenario for data generator
                             (infostealer-outbreak, executive-compromise,
                              session-hijack, mass-credential-dump,
                              reinfection-campaign)
  --purple-scenario NAME     Purple team scenario to run
                             (credential-stuffing, session-hijack,
                              ransomware-precursor, insider-threat,
                              supply-chain, mfa-fatigue, identity-pivot,
                              cap-breach)
  --generate-only            Only generate files, skip ingestion/validation
  --skip-validation          Skip the ingestion validation step
  --skip-analytics           Skip running sample analytic rules
  --output-dir DIR           Output directory for generated files
                             (default: ./spycloud-test-data)
  --wait-minutes N           Minutes to wait for ingestion (default: 10)
  -h, --help                 Show this help

Examples:
  $(basename "$0") -g myRG -w myWorkspace --count 25
  $(basename "$0") --generate-only --count 50
  $(basename "$0") -g myRG -w myWorkspace --purple-scenario ransomware-precursor
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -g|--resource-group) RESOURCE_GROUP="$2"; shift 2;;
        -w|--workspace)      WORKSPACE="$2"; shift 2;;
        --count)             RECORD_COUNT="$2"; shift 2;;
        --scenario)          SCENARIO="$2"; shift 2;;
        --purple-scenario)   PURPLE_SCENARIO="$2"; shift 2;;
        --generate-only)     GENERATE_ONLY=true; shift;;
        --skip-validation)   SKIP_VALIDATION=true; shift;;
        --skip-analytics)    SKIP_ANALYTICS=true; shift;;
        --output-dir)        OUTPUT_DIR="$2"; shift 2;;
        --wait-minutes)      WAIT_MINUTES="$2"; shift 2;;
        -h|--help)           usage;;
        *) warn "Unknown option: $1"; shift;;
    esac
done

# ─── Validation ───────────────────────────────────────────────────────────────
show_banner

if [[ "$GENERATE_ONLY" == "false" ]]; then
    if [[ -z "$RESOURCE_GROUP" || -z "$WORKSPACE" ]]; then
        err "Resource group (-g) and workspace (-w) are required unless --generate-only is set."
        echo ""
        usage
    fi
fi

# Check Python
if ! command -v python3 &>/dev/null; then
    err "python3 is required but not found in PATH."
    exit 1
fi
ok "Python3 found: $(python3 --version 2>&1)"

# Check generator scripts exist
SIM_SCRIPT="${SCRIPT_DIR}/simulation-data-generator.py"
PURPLE_SCRIPT="${SCRIPT_DIR}/purple-team-scenarios.py"

if [[ ! -f "$SIM_SCRIPT" ]]; then
    err "Simulation data generator not found: $SIM_SCRIPT"
    exit 1
fi
if [[ ! -f "$PURPLE_SCRIPT" ]]; then
    err "Purple team scenario engine not found: $PURPLE_SCRIPT"
    exit 1
fi
ok "Generator scripts found"

# ─── Helper: get workspace credentials ────────────────────────────────────────
get_workspace_credentials() {
    if [[ -n "${LOG_ANALYTICS_WORKSPACE_ID:-}" && -n "${LOG_ANALYTICS_SHARED_KEY:-}" ]]; then
        log "Using workspace credentials from environment variables"
        return 0
    fi

    log "Retrieving workspace credentials from Azure..."
    if ! az account show &>/dev/null; then
        err "Not logged in to Azure CLI. Run: az login"
        exit 1
    fi

    export LOG_ANALYTICS_WORKSPACE_ID
    LOG_ANALYTICS_WORKSPACE_ID=$(az monitor log-analytics workspace show \
        --resource-group "$RESOURCE_GROUP" \
        --workspace-name "$WORKSPACE" \
        --query customerId -o tsv 2>/dev/null)

    if [[ -z "$LOG_ANALYTICS_WORKSPACE_ID" ]]; then
        err "Failed to get workspace ID. Verify resource group and workspace name."
        exit 1
    fi

    export LOG_ANALYTICS_SHARED_KEY
    LOG_ANALYTICS_SHARED_KEY=$(az monitor log-analytics workspace get-shared-keys \
        --resource-group "$RESOURCE_GROUP" \
        --workspace-name "$WORKSPACE" \
        --query primarySharedKey -o tsv 2>/dev/null)

    if [[ -z "$LOG_ANALYTICS_SHARED_KEY" ]]; then
        err "Failed to get workspace shared key. Check permissions."
        exit 1
    fi

    ok "Workspace ID: ${LOG_ANALYTICS_WORKSPACE_ID:0:8}...  (retrieved)"
}


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 1: Generate test data
# ═══════════════════════════════════════════════════════════════════════════════
step "Phase 1: Generating Synthetic Test Data"

mkdir -p "$OUTPUT_DIR"

if [[ -n "$SCENARIO" ]]; then
    log "Running simulation scenario: $SCENARIO (${RECORD_COUNT} records/table)"
    python3 "$SIM_SCRIPT" \
        --scenario "$SCENARIO" \
        --count "$RECORD_COUNT" \
        --output file \
        --output-dir "$OUTPUT_DIR" \
        2>&1 | while IFS= read -r line; do log "  [sim] $line"; done
else
    log "Generating data for ALL tables (${RECORD_COUNT} records/table)"
    python3 "$SIM_SCRIPT" \
        --table all \
        --count "$RECORD_COUNT" \
        --output file \
        --output-dir "$OUTPUT_DIR" \
        2>&1 | while IFS= read -r line; do log "  [sim] $line"; done
fi

# Count generated files
FILE_COUNT=$(find "$OUTPUT_DIR" -name "*.json" -type f | wc -l)
TOTAL_RECORDS=0
for f in "$OUTPUT_DIR"/*.json; do
    if [[ -f "$f" ]]; then
        count=$(python3 -c "import json; print(len(json.load(open('$f'))))" 2>/dev/null || echo 0)
        TOTAL_RECORDS=$((TOTAL_RECORDS + count))
    fi
done

ok "Generated ${TOTAL_RECORDS} records across ${FILE_COUNT} files in ${OUTPUT_DIR}/"

# Purple team scenario (if requested)
if [[ -n "$PURPLE_SCENARIO" ]]; then
    step "Phase 1b: Generating Purple Team Scenario"
    PURPLE_DIR="${OUTPUT_DIR}/purple-team"
    log "Running purple team scenario: $PURPLE_SCENARIO"
    python3 "$PURPLE_SCRIPT" \
        --scenario "$PURPLE_SCENARIO" \
        --intensity medium \
        --teach-agent \
        --output file \
        --output-dir "$PURPLE_DIR" \
        2>&1 | while IFS= read -r line; do log "  [purple] $line"; done
    PURPLE_FILES=$(find "$PURPLE_DIR" -name "*.json" -type f 2>/dev/null | wc -l)
    ok "Purple team: ${PURPLE_FILES} files generated in ${PURPLE_DIR}/"
fi

# Exit early if generate-only mode
if [[ "$GENERATE_ONLY" == "true" ]]; then
    step "Complete (Generate Only Mode)"
    ok "Test data generated in: $(realpath "$OUTPUT_DIR")"
    log "To ingest this data, re-run with -g and -w flags (without --generate-only)."
    exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 2: Ingest data into Log Analytics
# ═══════════════════════════════════════════════════════════════════════════════
step "Phase 2: Ingesting Data into Log Analytics"

get_workspace_credentials

log "Sending data to workspace: $WORKSPACE"

if [[ -n "$SCENARIO" ]]; then
    python3 "$SIM_SCRIPT" \
        --scenario "$SCENARIO" \
        --count "$RECORD_COUNT" \
        --output sentinel \
        --workspace-id "$LOG_ANALYTICS_WORKSPACE_ID" \
        --shared-key "$LOG_ANALYTICS_SHARED_KEY" \
        2>&1 | while IFS= read -r line; do log "  [ingest] $line"; done
else
    python3 "$SIM_SCRIPT" \
        --table all \
        --count "$RECORD_COUNT" \
        --output sentinel \
        --workspace-id "$LOG_ANALYTICS_WORKSPACE_ID" \
        --shared-key "$LOG_ANALYTICS_SHARED_KEY" \
        2>&1 | while IFS= read -r line; do log "  [ingest] $line"; done
fi

ok "Data submitted to Log Analytics ingestion pipeline"
log "Note: Data typically takes 5-15 minutes to appear in tables."

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 3: Wait for ingestion
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$SKIP_VALIDATION" == "false" ]]; then
    step "Phase 3: Waiting for Data Ingestion (${WAIT_MINUTES} minutes)"

    log "Waiting ${WAIT_MINUTES} minutes for data to appear in Log Analytics..."
    WAIT_SECONDS=$((WAIT_MINUTES * 60))
    INTERVAL=30
    ELAPSED_WAIT=0

    while [[ $ELAPSED_WAIT -lt $WAIT_SECONDS ]]; do
        remaining=$(( (WAIT_SECONDS - ELAPSED_WAIT) / 60 ))
        echo -ne "\r${DIM}  Waiting... ${remaining} minutes remaining${NC}     "
        sleep $INTERVAL
        ELAPSED_WAIT=$((ELAPSED_WAIT + INTERVAL))
    done
    echo ""
    ok "Wait complete."

    # ═══════════════════════════════════════════════════════════════════════════
    #  PHASE 4: Validate data in tables
    # ═══════════════════════════════════════════════════════════════════════════
    step "Phase 4: Validating Data in Tables"

    TABLES_OK=0
    TABLES_EMPTY=0
    TABLES_ERROR=0
    VALIDATION_RESULTS=""

    for TABLE in "${SPYCLOUD_TABLES[@]}"; do
        echo -n "  Checking ${TABLE}... "

        QUERY="${TABLE} | summarize Count=count() | project Count"
        RESULT=$(az monitor log-analytics query \
            --workspace "$LOG_ANALYTICS_WORKSPACE_ID" \
            --analytics-query "$QUERY" \
            --timespan "PT1H" \
            -o json 2>/dev/null || echo "ERROR")

        if [[ "$RESULT" == "ERROR" ]]; then
            echo -e "${YELLOW}error (table may not exist)${NC}"
            TABLES_ERROR=$((TABLES_ERROR + 1))
            VALIDATION_RESULTS="${VALIDATION_RESULTS}\n  ${YELLOW}ERROR${NC}  ${TABLE}"
        else
            COUNT=$(echo "$RESULT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if isinstance(data, list) and len(data) > 0:
        print(data[0].get('Count', 0))
    else:
        print(0)
except:
    print(0)
" 2>/dev/null || echo "0")

            if [[ "$COUNT" -gt 0 ]]; then
                echo -e "${GREEN}${COUNT} records${NC}"
                TABLES_OK=$((TABLES_OK + 1))
                VALIDATION_RESULTS="${VALIDATION_RESULTS}\n  ${GREEN}  OK ${NC}  ${TABLE}: ${COUNT} records"
            else
                echo -e "${YELLOW}empty${NC}"
                TABLES_EMPTY=$((TABLES_EMPTY + 1))
                VALIDATION_RESULTS="${VALIDATION_RESULTS}\n  ${YELLOW}EMPTY${NC}  ${TABLE}"
            fi
        fi
    done

    echo ""
    log "Validation Summary:"
    echo -e "$VALIDATION_RESULTS"
    echo ""
    ok "Tables with data: ${TABLES_OK}/${#SPYCLOUD_TABLES[@]}"
    if [[ $TABLES_EMPTY -gt 0 ]]; then
        warn "Empty tables: ${TABLES_EMPTY} (may need more time for ingestion)"
    fi
    if [[ $TABLES_ERROR -gt 0 ]]; then
        warn "Tables with errors: ${TABLES_ERROR} (may not be deployed)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 5: Run sample analytic rules against the data
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$SKIP_ANALYTICS" == "false" && "$SKIP_VALIDATION" == "false" ]]; then
    step "Phase 5: Running Sample Analytic Rules"

    declare -A SAMPLE_RULES
    SAMPLE_RULES["High Severity Exposures"]="SpyCloudBreachWatchlist_CL | where severity >= 20 | summarize Count=count(), Users=dcount(email) | project Count, Users"
    SAMPLE_RULES["Infostealer Detections"]="SpyCloudCompassData_CL | where malware_family != '' | summarize Count=count(), Families=make_set(malware_family) | project Count, Families"
    SAMPLE_RULES["Stolen Session Cookies"]="SpyCloudSipCookies_CL | where severity >= 20 | summarize Count=count(), Domains=dcount(target_domain) | project Count, Domains"
    SAMPLE_RULES["Identity Links Detected"]="SpyCloudIdLink_CL | where link_strength > 0.7 | summarize Count=count(), AvgStrength=avg(link_strength) | project Count, AvgStrength"
    SAMPLE_RULES["CAP Actions"]="SpyCloudCAP_CL | summarize Count=count(), Succeeded=countif(action_status == 'success'), Failed=countif(action_status == 'failed') | project Count, Succeeded, Failed"
    SAMPLE_RULES["Unremediated High Severity"]="let remediated = SpyCloud_ConditionalAccessLogs_CL | distinct Email; SpyCloudBreachWatchlist_CL | where severity >= 20 | where email !in (remediated) | summarize Count=count(), MaxSeverity=max(severity) | project Count, MaxSeverity"
    SAMPLE_RULES["Critical Risk Exposures"]="SpyCloudExposure_CL | where risk_score >= 80 | summarize Count=count(), AvgScore=avg(risk_score) | project Count, AvgScore"
    SAMPLE_RULES["MDE Isolation Actions"]="Spycloud_MDE_Logs_CL | where Action == 'Isolate' | summarize Count=count(), Succeeded=countif(ActionStatus == 'Succeeded') | project Count, Succeeded"

    RULES_PASSED=0
    RULES_FAILED=0
    RULES_RESULTS=""

    for RULE_NAME in "${!SAMPLE_RULES[@]}"; do
        QUERY="${SAMPLE_RULES[$RULE_NAME]}"
        echo -n "  Testing: ${RULE_NAME}... "

        RESULT=$(az monitor log-analytics query \
            --workspace "$LOG_ANALYTICS_WORKSPACE_ID" \
            --analytics-query "$QUERY" \
            --timespan "PT2H" \
            -o json 2>/dev/null || echo "ERROR")

        if [[ "$RESULT" == "ERROR" ]]; then
            echo -e "${RED}FAILED${NC}"
            RULES_FAILED=$((RULES_FAILED + 1))
            RULES_RESULTS="${RULES_RESULTS}\n  ${RED}FAIL${NC}  ${RULE_NAME}: query error"
        else
            COUNT=$(echo "$RESULT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if isinstance(data, list) and len(data) > 0:
        row = data[0]
        count = row.get('Count', 0)
        print(int(count) if count else 0)
    else:
        print(0)
except:
    print(0)
" 2>/dev/null || echo "0")

            if [[ "$COUNT" -gt 0 ]]; then
                echo -e "${GREEN}PASSED (${COUNT} matches)${NC}"
                RULES_PASSED=$((RULES_PASSED + 1))
                RULES_RESULTS="${RULES_RESULTS}\n  ${GREEN}PASS${NC}  ${RULE_NAME}: ${COUNT} matches"
            else
                echo -e "${YELLOW}NO MATCHES${NC}"
                RULES_RESULTS="${RULES_RESULTS}\n  ${YELLOW}NONE${NC}  ${RULE_NAME}: 0 matches"
            fi
        fi
    done

    echo ""
    log "Analytic Rule Test Results:"
    echo -e "$RULES_RESULTS"
    echo ""
    ok "Rules passed: ${RULES_PASSED}/${#SAMPLE_RULES[@]}"
    if [[ $RULES_FAILED -gt 0 ]]; then
        warn "Rules failed: ${RULES_FAILED}"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  Summary
# ═══════════════════════════════════════════════════════════════════════════════
step "Deployment Complete"

echo -e "${BOLD}Summary:${NC}"
echo -e "  Workspace:      ${WORKSPACE}"
echo -e "  Resource Group:  ${RESOURCE_GROUP}"
echo -e "  Records/table:   ${RECORD_COUNT}"
echo -e "  Output dir:      $(realpath "$OUTPUT_DIR")"
echo -e "  Log file:        ${LOGFILE}"
echo -e "  Elapsed:         $(elapsed)"
echo ""

if [[ "$SKIP_VALIDATION" == "false" ]]; then
    echo -e "  ${GREEN}Tables validated:${NC}  ${TABLES_OK:-0}/${#SPYCLOUD_TABLES[@]}"
fi
if [[ "$SKIP_ANALYTICS" == "false" && "$SKIP_VALIDATION" == "false" ]]; then
    echo -e "  ${GREEN}Rules tested:${NC}      ${RULES_PASSED:-0}/${#SAMPLE_RULES[@]}"
fi

echo ""
log "Next steps:"
log "  1. Open Microsoft Sentinel and verify data in custom tables"
log "  2. Run workbooks to visualize the test data"
log "  3. Check that analytic rules fire on the synthetic data"
log "  4. Test playbook triggers with the generated incidents"
echo ""
ok "Test data deployment complete!"
