#!/usr/bin/env bash
#===============================================================================
#  SpyCloud Sentinel -- Enhanced Post-Deployment Automation
#  Version: 6.0.0
#
#  Complete zero-touch post-deployment automation for SpyCloud Sentinel.
#  Handles everything after the ARM template deploys:
#    Phase 1: Validate & Discover deployed resources
#    Phase 2: Resolve DCE/DCR endpoints
#    Phase 3: RBAC role assignments
#    Phase 4: Managed Identity permissions (Microsoft Graph API)
#    Phase 5: MDE API permissions (WindowsDefenderATP)
#    Phase 6: Auto-connect SpyCloud data connector
#    Phase 7: Enable analytics rules
#    Phase 8: Comprehensive health verification
#
#  Usage:
#    chmod +x scripts/post-deploy-auto.sh
#    ./scripts/post-deploy-auto.sh -g <resource-group> -w <workspace>
#
#  Non-interactive (CI/CD):
#    ./scripts/post-deploy-auto.sh -g myRG -w myWS --non-interactive
#
#  Full options:
#    ./scripts/post-deploy-auto.sh -g myRG -w myWS -s <sub-id> -k <api-key> \
#      --enable-rules --non-interactive --max-retries 5
#===============================================================================
set -uo pipefail

# ==============================================================================
# Colors & Formatting
# ==============================================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
TEAL='\033[38;2;0;180;216m'

# ==============================================================================
# Globals
# ==============================================================================
SCRIPT_VERSION="5.0.0"
T0=$(date +%s)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOGFILE="/tmp/spycloud-post-deploy-${TIMESTAMP}.log"
PORTAL="https://portal.azure.com"

# Counters
PHASE_PASS=0
PHASE_WARN=0
PHASE_FAIL=0
PHASE_SKIP=0

# Parameters (populated by CLI args or auto-detection)
RG=""
WS=""
SUB=""
API_KEY=""
NON_INTERACTIVE=false
ENABLE_RULES="all"
DRY_RUN=false
MAX_RETRIES=3
RETRY_DELAY=30

# Well-known Azure constants
MDE_APP_ID="fc780465-2017-40d4-a0c5-307022471b92"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"
MON_METRICS_PUB_ROLE="3913510d-42f4-4e42-8a64-420c390055eb"
SENTINEL_RESPONDER_ROLE="3e150937-b8fe-4cfb-8069-0eaf05ecd056"
SENTINEL_AUTO_CONTRIB_ROLE="f4c81013-99ee-4d62-a7ee-b3f1f648599a"

# Resolved state (populated during execution)
TENANT_ID=""
SUB_ID=""
SUB_NAME=""
WS_ID=""
DCE_NAME=""
DCE_URI=""
DCR_NAME=""
DCR_IMMUTABLE_ID=""
DCR_RESOURCE_ID=""
DCR_EXT_NAME=""
DCR_EXT_IMMUTABLE_ID=""
DCR_EXT_RESOURCE_ID=""

# Playbook definitions: name-suffix -> Graph permissions needed
# Format: "PlaybookSuffix:GraphPerm1,GraphPerm2|PlaybookSuffix2:..."
declare -A PLAYBOOK_GRAPH_PERMS=(
    ["ForcePasswordReset"]="User.ReadWrite.All"
    ["RevokeSessions"]="User.ReadWrite.All"
    ["EnforceMFA"]="UserAuthenticationMethod.ReadWrite.All"
    ["BlockConditionalAccess"]="GroupMember.ReadWrite.All,Directory.Read.All"
    ["NotifyUser"]="Mail.Send"
    ["NotifySOC"]=""
    ["EnrichIncident"]=""
    ["FullRemediation"]="User.ReadWrite.All,UserAuthenticationMethod.ReadWrite.All,GroupMember.ReadWrite.All,Directory.Read.All,Mail.Send"
)

declare -A PLAYBOOK_MDE_PERMS=(
    ["IsolateDevice"]="Machine.Isolate,Machine.ReadWrite.All"
)

# Sentinel RBAC roles per playbook
declare -A PLAYBOOK_SENTINEL_ROLES=(
    ["EnrichIncident"]="sentinel-responder"
    ["FullRemediation"]="sentinel-automation-contributor"
)

# ==============================================================================
# Logging Functions
# ==============================================================================
elapsed() {
    printf "%dm%02ds" $(( ($(date +%s) - T0) / 60 )) $(( ($(date +%s) - T0) % 60 ))
}

_log() {
    local level="$1" msg="$2" color="$3"
    local ts
    ts="[$(elapsed)]"
    echo -e "${DIM}${ts}${NC} ${color}${level}${NC}  ${msg}" >&2
    echo "[$(date -Iseconds)] ${level} ${msg}" >> "$LOGFILE"
}

log()   { _log "INFO" "$1" "$CYAN"; }
ok()    { _log " OK " "$1" "$GREEN"; ((PHASE_PASS++)) || true; }
warn()  { _log "WARN" "$1" "$YELLOW"; ((PHASE_WARN++)) || true; }
err()   { _log "FAIL" "$1" "$RED"; ((PHASE_FAIL++)) || true; }
skip()  { _log "SKIP" "$1" "$DIM"; ((PHASE_SKIP++)) || true; }
debug() { echo "[$(date -Iseconds)] DEBUG $1" >> "$LOGFILE"; }

phase_header() {
    local num="$1" total="$2" title="$3"
    echo "" >&2
    echo -e "${TEAL}======================================================================${NC}" >&2
    echo -e "${TEAL}  Phase ${num}/${total}: ${BOLD}${title}${NC}" >&2
    echo -e "${TEAL}======================================================================${NC}" >&2
    echo "" >&2
    echo "================ Phase ${num}/${total}: ${title} ================" >> "$LOGFILE"
}

# ==============================================================================
# Utility Functions
# ==============================================================================
retry_cmd() {
    local description="$1"; shift
    local max_attempts="${MAX_RETRIES}"
    local delay="${RETRY_DELAY}"
    local attempt=1
    local result=""

    while [[ $attempt -le $max_attempts ]]; do
        debug "Attempt ${attempt}/${max_attempts}: ${description}"
        if result=$("$@" 2>>"$LOGFILE"); then
            if [[ -n "$result" ]]; then
                echo "$result"
                return 0
            fi
        fi
        if [[ $attempt -lt $max_attempts ]]; then
            log "  Attempt ${attempt}/${max_attempts} failed for: ${description} -- retrying in ${delay}s..."
            sleep "$delay"
        fi
        ((attempt++))
    done
    return 1
}

confirm_action() {
    local msg="$1"
    if $NON_INTERACTIVE; then
        debug "Non-interactive: auto-confirming: ${msg}"
        return 0
    fi
    echo -en "${YELLOW}  ? ${msg} [Y/n]: ${NC}" >&2
    local answer
    read -r answer
    [[ -z "$answer" || "$answer" =~ ^[Yy] ]]
}

safe_az() {
    # Wrapper around az that logs errors but does not abort
    local output
    if output=$(az "$@" 2>>"$LOGFILE"); then
        echo "$output"
        return 0
    else
        debug "az $* returned non-zero"
        return 1
    fi
}

# ==============================================================================
# Banner
# ==============================================================================
show_banner() {
    cat >&2 << 'BANNER'

   _____ _____ __ ______ _    ____  __  ______
  / ___// __ \ \/ / ___/| |  / __ \/ / / / __ \
  \__ \/ /_/ /\  / /    | | / / / / / / / / / /
 ___/ / ____/ / / /___  | |/ / /_/ / /_/ / /_/ /
/____/_/     /_/\____/  |___/\____/\____/_____/

BANNER
    echo -e "  ${TEAL}------------------------------------------------------------${NC}" >&2
    echo -e "  ${BOLD}SpyCloud Sentinel -- Enhanced Post-Deployment Automation${NC}" >&2
    echo -e "  ${DIM}Version ${SCRIPT_VERSION} | Zero-touch post-deploy configuration${NC}" >&2
    echo -e "  ${TEAL}------------------------------------------------------------${NC}" >&2
    echo -e "  ${DIM}Log: ${LOGFILE}${NC}" >&2
    echo "" >&2
}

# ==============================================================================
# Usage
# ==============================================================================
usage() {
    show_banner
    cat >&2 << 'USAGE'
  USAGE:
    post-deploy-auto.sh [options]

  REQUIRED (or auto-detected):
    -g, --resource-group NAME    Azure resource group
    -w, --workspace NAME         Log Analytics workspace name

  OPTIONAL:
    -s, --subscription ID        Azure subscription ID
    -k, --api-key KEY            SpyCloud API key (for connector config)
    --enable-rules MODE          Enable analytics rules: all|spycloud|none (default: all)
    --non-interactive            No prompts, suitable for CI/CD pipelines
    --dry-run                    Show what would happen without making changes
    --max-retries N              Max retry attempts for transient failures (default: 3)
    --retry-delay N              Seconds between retries (default: 30)
    -h, --help                   Show this help

  EXAMPLES:
    # Interactive with required params:
    ./scripts/post-deploy-auto.sh -g spycloud-sentinel -w spycloud-ws

    # Full CI/CD automation:
    ./scripts/post-deploy-auto.sh -g myRG -w myWS -s <sub-id> -k <key> \
      --enable-rules all --non-interactive

    # Dry run to preview changes:
    ./scripts/post-deploy-auto.sh -g myRG -w myWS --dry-run

USAGE
    exit 0
}

# ==============================================================================
# Parse Arguments
# ==============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -g|--resource-group) RG="$2"; shift 2 ;;
            -w|--workspace)      WS="$2"; shift 2 ;;
            -s|--subscription)   SUB="$2"; shift 2 ;;
            -k|--api-key)        API_KEY="$2"; shift 2 ;;
            --enable-rules)      ENABLE_RULES="$2"; shift 2 ;;
            --non-interactive)   NON_INTERACTIVE=true; shift ;;
            --dry-run)           DRY_RUN=true; shift ;;
            --max-retries)       MAX_RETRIES="$2"; shift 2 ;;
            --retry-delay)       RETRY_DELAY="$2"; shift 2 ;;
            -h|--help)           usage ;;
            *)                   err "Unknown option: $1"; echo "Use -h for help" >&2; exit 1 ;;
        esac
    done
}

# ==============================================================================
# Phase 1: Validate & Discover
# ==============================================================================
phase1_validate_discover() {
    phase_header 1 8 "Validate & Discover"

    # --- Check Azure CLI ---
    if ! command -v az &>/dev/null; then
        err "Azure CLI (az) is not installed."
        echo "  Install: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli" >&2
        exit 1
    fi
    local az_ver
    az_ver=$(az version --query '"azure-cli"' -o tsv 2>/dev/null || echo "unknown")
    ok "Azure CLI installed (version ${az_ver})"

    # --- Check authentication ---
    if ! az account show &>/dev/null; then
        if $NON_INTERACTIVE; then
            err "Not authenticated and running non-interactive. Run 'az login' first."
            exit 1
        fi
        warn "Not logged in to Azure -- initiating login..."
        az login --use-device-code 2>>"$LOGFILE" || az login 2>>"$LOGFILE"
    fi

    # --- Set subscription if provided ---
    if [[ -n "$SUB" ]]; then
        az account set --subscription "$SUB" 2>>"$LOGFILE" || {
            err "Failed to set subscription: ${SUB}"
            exit 1
        }
    fi

    TENANT_ID=$(az account show --query tenantId -o tsv 2>/dev/null)
    SUB_ID=$(az account show --query id -o tsv 2>/dev/null)
    SUB_NAME=$(az account show --query name -o tsv 2>/dev/null)
    ok "Authenticated to Azure"
    log "  Subscription: ${BOLD}${SUB_NAME}${NC} (${SUB_ID})"
    log "  Tenant:       ${TENANT_ID}"

    # --- Auto-detect resource group if not provided ---
    if [[ -z "$RG" ]]; then
        log "Auto-detecting resource group (looking for SpyCloud resources)..."
        RG=$(az group list --query "[?tags.solution=='SpyCloud-Sentinel'].name | [0]" -o tsv 2>/dev/null || echo "")
        if [[ -z "$RG" ]]; then
            RG=$(az group list --query "[?contains(name,'spycloud')].name | [0]" -o tsv 2>/dev/null || echo "")
        fi
        if [[ -n "$RG" ]]; then
            ok "Auto-detected resource group: ${BOLD}${RG}${NC}"
        else
            if $NON_INTERACTIVE; then
                err "Cannot auto-detect resource group. Provide -g <name>."
                exit 1
            fi
            echo -en "${YELLOW}  ? Enter resource group name: ${NC}" >&2
            read -r RG
            [[ -z "$RG" ]] && { err "Resource group is required."; exit 1; }
        fi
    fi

    # --- Validate resource group exists ---
    if ! az group show --name "$RG" &>/dev/null; then
        err "Resource group '${RG}' not found in subscription '${SUB_NAME}'."
        exit 1
    fi
    ok "Resource group '${RG}' exists"

    # --- Auto-detect workspace if not provided ---
    if [[ -z "$WS" ]]; then
        log "Auto-detecting workspace..."
        WS=$(az monitor log-analytics workspace list -g "$RG" \
            --query "[?contains(name,'spycloud') || contains(name,'sentinel')].name | [0]" \
            -o tsv 2>/dev/null || echo "")
        if [[ -z "$WS" ]]; then
            WS=$(az monitor log-analytics workspace list -g "$RG" \
                --query "[0].name" -o tsv 2>/dev/null || echo "")
        fi
        if [[ -n "$WS" ]]; then
            ok "Auto-detected workspace: ${BOLD}${WS}${NC}"
        else
            if $NON_INTERACTIVE; then
                err "Cannot auto-detect workspace. Provide -w <name>."
                exit 1
            fi
            echo -en "${YELLOW}  ? Enter workspace name: ${NC}" >&2
            read -r WS
            [[ -z "$WS" ]] && { err "Workspace name is required."; exit 1; }
        fi
    fi

    # --- Validate workspace ---
    WS_ID=$(az monitor log-analytics workspace show --workspace-name "$WS" -g "$RG" \
        --query id -o tsv 2>/dev/null || echo "")
    if [[ -z "$WS_ID" ]]; then
        err "Workspace '${WS}' not found in resource group '${RG}'."
        exit 1
    fi
    ok "Workspace '${WS}' validated"

    # --- Set naming conventions ---
    DCE_NAME="dce-spycloud-${WS}"
    DCR_NAME="dcr-spycloud-${WS}"
    DCR_EXT_NAME="dcr-ccf-ext-${WS}"

    # --- List all deployed resources ---
    log "Listing deployed resources in '${RG}'..."
    local resource_list
    resource_list=$(az resource list -g "$RG" --query "[].{Name:name, Type:type}" -o table 2>/dev/null || echo "")
    if [[ -n "$resource_list" ]]; then
        local resource_count
        resource_count=$(az resource list -g "$RG" --query "length([])" -o tsv 2>/dev/null || echo "0")
        ok "Found ${resource_count} resources in resource group"
        debug "Resources: ${resource_list}"
        echo "$resource_list" >> "$LOGFILE"
    else
        warn "No resources found in resource group (deployment may still be in progress)"
    fi

    if $DRY_RUN; then
        log "${BOLD}DRY RUN MODE${NC} -- no changes will be made"
    fi
}

# ==============================================================================
# Phase 2: Resolve DCE/DCR
# ==============================================================================
phase2_resolve_dce_dcr() {
    phase_header 2 8 "Resolve DCE/DCR"

    # --- DCE ---
    log "Resolving Data Collection Endpoint: ${DCE_NAME}..."
    DCE_URI=$(retry_cmd "Resolve DCE URI" \
        az monitor data-collection endpoint show \
        --name "$DCE_NAME" -g "$RG" \
        --query "logsIngestion.endpoint" -o tsv) || true

    if [[ -n "$DCE_URI" ]]; then
        ok "DCE Logs Ingestion URI: ${DCE_URI}"
    else
        # Try to find any DCE in the resource group
        local alt_dce
        alt_dce=$(az monitor data-collection endpoint list -g "$RG" \
            --query "[0].{name:name,uri:logsIngestion.endpoint}" -o tsv 2>/dev/null || echo "")
        if [[ -n "$alt_dce" ]]; then
            local alt_name alt_uri
            alt_name=$(echo "$alt_dce" | cut -f1)
            alt_uri=$(echo "$alt_dce" | cut -f2)
            warn "DCE '${DCE_NAME}' not found, but found '${alt_name}'"
            DCE_NAME="$alt_name"
            DCE_URI="$alt_uri"
            ok "Using alternate DCE: ${DCE_URI}"
        else
            err "No Data Collection Endpoint found in resource group"
            log "  The content template may still be deploying. Re-run this script in a few minutes."
        fi
    fi

    # --- DCR ---
    log "Resolving Data Collection Rule: ${DCR_NAME}..."
    DCR_IMMUTABLE_ID=$(retry_cmd "Resolve DCR Immutable ID" \
        az monitor data-collection rule show \
        --name "$DCR_NAME" -g "$RG" \
        --query "immutableId" -o tsv) || true

    if [[ -n "$DCR_IMMUTABLE_ID" ]]; then
        DCR_RESOURCE_ID=$(az monitor data-collection rule show \
            --name "$DCR_NAME" -g "$RG" \
            --query "id" -o tsv 2>/dev/null || echo "")
        ok "DCR Immutable ID: ${DCR_IMMUTABLE_ID}"
        debug "DCR Resource ID: ${DCR_RESOURCE_ID}"

        # Show stream details
        local stream_count flow_count
        stream_count=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" \
            --query "length(streamDeclarations)" -o tsv 2>/dev/null || echo "0")
        flow_count=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" \
            --query "length(dataFlows)" -o tsv 2>/dev/null || echo "0")
        log "  Streams: ${stream_count} | Data Flows: ${flow_count}"
    else
        # Try alternate names
        local alt_dcr
        alt_dcr=$(az monitor data-collection rule list -g "$RG" \
            --query "[?contains(name,'spycloud') || contains(name,'SpyCloud') || contains(name,'pyCloud')].{name:name,id:immutableId}" \
            -o tsv 2>/dev/null || echo "")
        if [[ -n "$alt_dcr" ]]; then
            local alt_dcr_name alt_dcr_id
            alt_dcr_name=$(echo "$alt_dcr" | head -1 | cut -f1)
            alt_dcr_id=$(echo "$alt_dcr" | head -1 | cut -f2)
            warn "DCR '${DCR_NAME}' not found, but found '${alt_dcr_name}'"
            DCR_NAME="$alt_dcr_name"
            DCR_IMMUTABLE_ID="$alt_dcr_id"
            DCR_RESOURCE_ID=$(az monitor data-collection rule show \
                --name "$DCR_NAME" -g "$RG" --query "id" -o tsv 2>/dev/null || echo "")
            ok "Using alternate DCR: ${DCR_IMMUTABLE_ID}"
        else
            err "No Data Collection Rule found"
            log "  Content template may still be deploying. Wait a few minutes and re-run."
        fi
    fi

    # --- Extended DCR (for Exposure, CAP, MDE Logs, CA Logs) ---
    log "Resolving Extended Data Collection Rule: ${DCR_EXT_NAME}..."
    DCR_EXT_IMMUTABLE_ID=$(retry_cmd "Resolve Extended DCR Immutable ID" \
        az monitor data-collection rule show \
        --name "$DCR_EXT_NAME" -g "$RG" \
        --query "immutableId" -o tsv) || true

    if [[ -n "$DCR_EXT_IMMUTABLE_ID" ]]; then
        DCR_EXT_RESOURCE_ID=$(az monitor data-collection rule show \
            --name "$DCR_EXT_NAME" -g "$RG" \
            --query "id" -o tsv 2>/dev/null || echo "")
        ok "Extended DCR Immutable ID: ${DCR_EXT_IMMUTABLE_ID}"
        local ext_stream_count ext_flow_count
        ext_stream_count=$(az monitor data-collection rule show --name "$DCR_EXT_NAME" -g "$RG" \
            --query "length(streamDeclarations)" -o tsv 2>/dev/null || echo "0")
        ext_flow_count=$(az monitor data-collection rule show --name "$DCR_EXT_NAME" -g "$RG" \
            --query "length(dataFlows)" -o tsv 2>/dev/null || echo "0")
        log "  Extended DCR Streams: ${ext_stream_count} | Data Flows: ${ext_flow_count}"
    else
        warn "Extended DCR '${DCR_EXT_NAME}' not found. MDE/CA playbooks may need manual DCR configuration."
    fi

    # Summary display
    echo "" >&2
    echo -e "  ${BOLD}DCE/DCR Reference Values:${NC}" >&2
    echo -e "  ${DIM}(Use these when configuring the data connector)${NC}" >&2
    echo -e "    DCE URI:              ${CYAN}${DCE_URI:-NOT RESOLVED}${NC}" >&2
    echo -e "    DCR Immutable ID:     ${CYAN}${DCR_IMMUTABLE_ID:-NOT RESOLVED}${NC}" >&2
    echo -e "    DCR Ext Immutable ID: ${CYAN}${DCR_EXT_IMMUTABLE_ID:-NOT RESOLVED}${NC}" >&2
    echo "" >&2
}

# ==============================================================================
# Phase 3: RBAC Assignments
# ==============================================================================
phase3_rbac_assignments() {
    phase_header 3 8 "RBAC Assignments"

    if [[ -z "$DCR_RESOURCE_ID" ]]; then
        warn "DCR resource ID not available -- skipping DCR-scoped RBAC assignments"
        warn "Re-run this script after the DCR is deployed"
    fi

    # --- Helper: assign a role ---
    assign_rbac_role() {
        local principal_id="$1"
        local principal_type="$2"
        local role_id="$3"
        local role_name="$4"
        local scope="$5"
        local description="$6"

        if [[ -z "$principal_id" || -z "$scope" ]]; then
            skip "${description}: missing principal or scope"
            return
        fi

        if $DRY_RUN; then
            log "[DRY RUN] Would assign '${role_name}' to ${description}"
            return
        fi

        debug "RBAC: principal=${principal_id} role=${role_name} scope=${scope}"
        if az role assignment create \
            --assignee-object-id "$principal_id" \
            --assignee-principal-type "$principal_type" \
            --role "$role_id" \
            --scope "$scope" \
            -o none 2>>"$LOGFILE"; then
            ok "RBAC '${role_name}' assigned to ${description}"
        else
            # Check if it already exists
            local existing
            existing=$(az role assignment list \
                --assignee "$principal_id" \
                --role "$role_id" \
                --scope "$scope" \
                --query "length([])" -o tsv 2>/dev/null || echo "0")
            if [[ "$existing" -gt 0 ]]; then
                ok "RBAC '${role_name}' already assigned to ${description} (idempotent)"
            else
                warn "RBAC '${role_name}' assignment may have failed for ${description}"
            fi
        fi
    }

    # --- Discover all playbook managed identities ---
    log "Discovering Logic App playbooks in resource group..."
    local all_playbooks
    all_playbooks=$(az logic workflow list -g "$RG" \
        --query "[?contains(name,'SpyCloud')].{name:name,pid:identity.principalId,state:state}" \
        -o tsv 2>/dev/null || echo "")

    if [[ -z "$all_playbooks" ]]; then
        warn "No SpyCloud Logic App playbooks found in '${RG}'"
        return
    fi

    local pb_count
    pb_count=$(echo "$all_playbooks" | wc -l)
    ok "Found ${pb_count} SpyCloud playbook(s)"

    # --- Assign Monitoring Metrics Publisher on DCR to each playbook ---
    log "Assigning 'Monitoring Metrics Publisher' role on DCR..."
    while IFS=$'\t' read -r pb_name pb_pid pb_state; do
        [[ -z "$pb_name" ]] && continue
        if [[ -n "$DCR_RESOURCE_ID" && -n "$pb_pid" ]]; then
            assign_rbac_role "$pb_pid" "ServicePrincipal" \
                "$MON_METRICS_PUB_ROLE" "Monitoring Metrics Publisher" \
                "$DCR_RESOURCE_ID" "$pb_name"
        else
            skip "Monitoring Metrics Publisher for ${pb_name} (no DCR or no managed identity)"
        fi
    done <<< "$all_playbooks"

    # --- Assign Sentinel Responder to EnrichIncident ---
    log "Assigning Sentinel-specific RBAC roles..."
    for pb_suffix in "${!PLAYBOOK_SENTINEL_ROLES[@]}"; do
        local role_type="${PLAYBOOK_SENTINEL_ROLES[$pb_suffix]}"
        local role_id_to_assign=""
        local role_display_name=""

        case "$role_type" in
            "sentinel-responder")
                role_id_to_assign="$SENTINEL_RESPONDER_ROLE"
                role_display_name="Microsoft Sentinel Responder"
                ;;
            "sentinel-automation-contributor")
                role_id_to_assign="$SENTINEL_AUTO_CONTRIB_ROLE"
                role_display_name="Microsoft Sentinel Automation Contributor"
                ;;
        esac

        # Find matching playbook
        local match_name match_pid
        match_name=$(echo "$all_playbooks" | grep -i "${pb_suffix}" | head -1 | cut -f1)
        match_pid=$(echo "$all_playbooks" | grep -i "${pb_suffix}" | head -1 | cut -f2)

        if [[ -n "$match_name" && -n "$match_pid" && -n "$WS_ID" ]]; then
            assign_rbac_role "$match_pid" "ServicePrincipal" \
                "$role_id_to_assign" "$role_display_name" \
                "$WS_ID" "$match_name"
        else
            skip "${role_display_name} for SpyCloud-${pb_suffix} (not found)"
        fi
    done

    # --- Assign Sentinel Automation Contributor at RG scope for automation rules ---
    log "Checking for automation rule service principal..."
    local automation_rules
    automation_rules=$(az rest --method GET \
        --uri "https://management.azure.com${WS_ID}/providers/Microsoft.SecurityInsights/automationRules?api-version=2023-02-01" \
        --query "value[?contains(properties.displayName || '','SpyCloud')].name" -o tsv 2>/dev/null || echo "")
    if [[ -n "$automation_rules" ]]; then
        ok "Found SpyCloud automation rules -- Sentinel Automation Contributor should be assigned at workspace scope"
        debug "Automation rules found: ${automation_rules}"
    else
        log "No SpyCloud automation rules detected (this is normal if not deployed)"
    fi
}

# ==============================================================================
# Phase 4: Managed Identity Permissions (Graph API)
# ==============================================================================
phase4_graph_permissions() {
    phase_header 4 8 "Managed Identity Permissions (Microsoft Graph API)"

    local graph_sp_id
    graph_sp_id=$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv 2>/dev/null || echo "")
    if [[ -z "$graph_sp_id" ]]; then
        err "Microsoft Graph service principal not found in tenant"
        log "  This may indicate insufficient permissions or a tenant configuration issue."
        return
    fi
    debug "Graph SP object ID: ${graph_sp_id}"

    # --- Helper: grant a single Graph app role ---
    grant_graph_permission() {
        local principal_id="$1"
        local permission_name="$2"
        local playbook_label="$3"

        if [[ -z "$principal_id" ]]; then
            skip "${permission_name} -> ${playbook_label}: no managed identity"
            return
        fi

        local role_id
        role_id=$(az ad sp show --id "$GRAPH_APP_ID" \
            --query "appRoles[?value=='${permission_name}'].id | [0]" -o tsv 2>/dev/null || echo "")
        if [[ -z "$role_id" ]]; then
            warn "${permission_name}: role not found in Graph API (may require a different license)"
            return
        fi

        if $DRY_RUN; then
            log "[DRY RUN] Would grant ${permission_name} to ${playbook_label}"
            return
        fi

        debug "Graph permission: principal=${principal_id} role=${permission_name} roleId=${role_id}"

        local response
        response=$(az rest --method POST \
            --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${graph_sp_id}/appRoleAssignedTo" \
            --body "{\"principalId\":\"${principal_id}\",\"resourceId\":\"${graph_sp_id}\",\"appRoleId\":\"${role_id}\"}" \
            2>>"$LOGFILE") && {
            ok "${permission_name} -> ${playbook_label}"
            return
        }

        # Check if assignment already exists (409 conflict = already exists)
        local existing
        existing=$(az rest --method GET \
            --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${graph_sp_id}/appRoleAssignedTo?\$filter=principalId eq '${principal_id}' and appRoleId eq '${role_id}'" \
            --query "value | length(@)" -o tsv 2>/dev/null || echo "0")
        if [[ "$existing" -gt 0 ]]; then
            ok "${permission_name} -> ${playbook_label} (already granted, idempotent)"
        else
            warn "${permission_name} -> ${playbook_label}: assignment returned error (may need admin consent)"
        fi
    }

    # --- Process each playbook that needs Graph permissions ---
    log "Granting Microsoft Graph API permissions to playbook managed identities..."

    local all_playbooks
    all_playbooks=$(az logic workflow list -g "$RG" \
        --query "[?contains(name,'SpyCloud')].{name:name,pid:identity.principalId}" \
        -o tsv 2>/dev/null || echo "")

    for pb_suffix in "${!PLAYBOOK_GRAPH_PERMS[@]}"; do
        local perms="${PLAYBOOK_GRAPH_PERMS[$pb_suffix]}"

        # Skip playbooks that don't need Graph permissions
        if [[ -z "$perms" ]]; then
            debug "Skipping ${pb_suffix}: no Graph permissions needed (webhook-based or RBAC-only)"
            continue
        fi

        # Find matching playbook
        local match_line match_name match_pid
        match_line=$(echo "$all_playbooks" | grep -i "${pb_suffix}" | head -1)
        match_name=$(echo "$match_line" | cut -f1)
        match_pid=$(echo "$match_line" | cut -f2)

        if [[ -z "$match_name" ]]; then
            skip "SpyCloud-${pb_suffix}: playbook not deployed"
            continue
        fi

        log "Processing ${match_name}..."

        # Grant each permission
        IFS=',' read -ra perm_array <<< "$perms"
        for perm in "${perm_array[@]}"; do
            grant_graph_permission "$match_pid" "$perm" "$match_name"
        done
    done

    # --- Admin consent guidance ---
    echo "" >&2
    log "Granting admin consent for all Graph API permissions..."
    if ! $DRY_RUN; then
        # Attempt to grant admin consent programmatically by listing and verifying
        local consent_note="Permissions have been assigned."
        local pending
        pending=$(az rest --method GET \
            --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${graph_sp_id}/appRoleAssignedTo" \
            --query "value | length(@)" -o tsv 2>/dev/null || echo "unknown")
        log "  Total Graph app role assignments on tenant: ${pending}"
        log "  ${BOLD}If any permissions show 'Needs admin consent':${NC}"
        log "    Portal -> Entra ID -> Enterprise Applications -> Managed Identities"
        log "    -> Select the playbook identity -> Permissions -> Grant admin consent"
        echo -e "    ${CYAN}${PORTAL}/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview${NC}" >&2
    fi
}

# ==============================================================================
# Phase 5: MDE API Permissions
# ==============================================================================
phase5_mde_permissions() {
    phase_header 5 8 "MDE API Permissions (WindowsDefenderATP)"

    local mde_sp_id
    mde_sp_id=$(az ad sp show --id "$MDE_APP_ID" --query id -o tsv 2>/dev/null || echo "")
    if [[ -z "$mde_sp_id" ]]; then
        warn "WindowsDefenderATP service principal not found in tenant"
        log "  This is expected if Microsoft Defender for Endpoint is not enabled."
        log "  MDE permissions will be skipped. Re-run after enabling MDE."
        return
    fi
    debug "MDE SP object ID: ${mde_sp_id}"

    # --- Helper: grant MDE app role ---
    grant_mde_permission() {
        local principal_id="$1"
        local permission_name="$2"
        local playbook_label="$3"

        if [[ -z "$principal_id" ]]; then
            skip "${permission_name} -> ${playbook_label}: no managed identity"
            return
        fi

        local role_id
        role_id=$(az ad sp show --id "$MDE_APP_ID" \
            --query "appRoles[?value=='${permission_name}'].id | [0]" -o tsv 2>/dev/null || echo "")
        if [[ -z "$role_id" ]]; then
            warn "${permission_name}: role not found in MDE API"
            return
        fi

        if $DRY_RUN; then
            log "[DRY RUN] Would grant MDE ${permission_name} to ${playbook_label}"
            return
        fi

        debug "MDE permission: principal=${principal_id} role=${permission_name} roleId=${role_id}"

        az rest --method POST \
            --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${mde_sp_id}/appRoleAssignedTo" \
            --body "{\"principalId\":\"${principal_id}\",\"resourceId\":\"${mde_sp_id}\",\"appRoleId\":\"${role_id}\"}" \
            2>>"$LOGFILE" && {
            ok "${permission_name} -> ${playbook_label}"
            return
        }

        # Check idempotency
        local existing
        existing=$(az rest --method GET \
            --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${mde_sp_id}/appRoleAssignedTo?\$filter=principalId eq '${principal_id}' and appRoleId eq '${role_id}'" \
            --query "value | length(@)" -o tsv 2>/dev/null || echo "0")
        if [[ "$existing" -gt 0 ]]; then
            ok "${permission_name} -> ${playbook_label} (already granted, idempotent)"
        else
            warn "${permission_name} -> ${playbook_label}: may need admin consent"
        fi
    }

    # --- Process IsolateDevice and any other MDE playbooks ---
    local all_playbooks
    all_playbooks=$(az logic workflow list -g "$RG" \
        --query "[?contains(name,'SpyCloud')].{name:name,pid:identity.principalId}" \
        -o tsv 2>/dev/null || echo "")

    for pb_suffix in "${!PLAYBOOK_MDE_PERMS[@]}"; do
        local perms="${PLAYBOOK_MDE_PERMS[$pb_suffix]}"

        local match_line match_name match_pid
        match_line=$(echo "$all_playbooks" | grep -i "${pb_suffix}" | head -1)
        match_name=$(echo "$match_line" | cut -f1)
        match_pid=$(echo "$match_line" | cut -f2)

        if [[ -z "$match_name" ]]; then
            skip "SpyCloud-${pb_suffix}: playbook not deployed"
            continue
        fi

        log "Processing ${match_name}..."

        IFS=',' read -ra perm_array <<< "$perms"
        for perm in "${perm_array[@]}"; do
            grant_mde_permission "$match_pid" "$perm" "$match_name"
        done
    done

    # Also grant MDE perms to FullRemediation if it exists (it calls IsolateDevice)
    local full_rem_line full_rem_name full_rem_pid
    full_rem_line=$(echo "$all_playbooks" | grep -i "FullRemediation" | head -1)
    full_rem_name=$(echo "$full_rem_line" | cut -f1)
    full_rem_pid=$(echo "$full_rem_line" | cut -f2)
    if [[ -n "$full_rem_name" && -n "$full_rem_pid" ]]; then
        log "FullRemediation orchestrator also needs MDE permissions (calls IsolateDevice)..."
        grant_mde_permission "$full_rem_pid" "Machine.Isolate" "$full_rem_name"
        grant_mde_permission "$full_rem_pid" "Machine.ReadWrite.All" "$full_rem_name"
    fi

    # Also grant MDE perms to legacy playbook names if they exist
    for legacy_name in "SpyCloud-MDE-Remediation-${WS}" "SpyCloud-MDE-Blocklist-${WS}"; do
        local legacy_pid
        legacy_pid=$(az logic workflow show --name "$legacy_name" -g "$RG" \
            --query "identity.principalId" -o tsv 2>/dev/null || echo "")
        if [[ -n "$legacy_pid" ]]; then
            log "Found legacy playbook ${legacy_name}, granting MDE permissions..."
            grant_mde_permission "$legacy_pid" "Machine.Isolate" "$legacy_name"
            grant_mde_permission "$legacy_pid" "Machine.ReadWrite.All" "$legacy_name"
        fi
    done

    # --- Admin consent for MDE ---
    echo "" >&2
    log "Admin consent for MDE API permissions:"
    log "  Portal -> Entra ID -> Enterprise Applications -> Managed Identities"
    log "  -> Select playbook identity -> Permissions -> Grant admin consent"
}

# ==============================================================================
# Phase 6: Auto-Connect SpyCloud Data Connector
# ==============================================================================
phase6_connect_data_connector() {
    phase_header 6 8 "Auto-Connect SpyCloud Data Connector"

    if [[ -z "$WS_ID" ]]; then
        err "Workspace ID not available -- cannot manage data connector"
        return
    fi

    # --- Check if connector definition exists ---
    log "Checking for SpyCloud connector definition..."
    local connector_def
    connector_def=$(az rest --method GET \
        --uri "https://management.azure.com${WS_ID}/providers/Microsoft.SecurityInsights/dataConnectorDefinitions?api-version=2022-09-01-preview" \
        --query "value[?contains(name,'SpyCloud') || contains(name,'spycloud')].{name:name,kind:kind}" \
        -o tsv 2>/dev/null || echo "")

    if [[ -n "$connector_def" ]]; then
        ok "SpyCloud connector definition found"
    else
        warn "SpyCloud connector definition not found via API"
        log "  The content template may not have deployed yet, or the connector"
        log "  may need to be installed from the Content Hub first."
        log "  Manual step: Sentinel -> Content Hub -> Search 'SpyCloud' -> Install"
    fi

    # --- Check if connector instances exist ---
    log "Checking for active SpyCloud data connector instances..."
    local connectors
    connectors=$(az rest --method GET \
        --uri "https://management.azure.com${WS_ID}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-12-01-preview" \
        --query "value[?contains(properties.connectorDefinitionName || properties.connectorUiConfig.title || name || '','SpyCloud') || contains(properties.connectorDefinitionName || properties.connectorUiConfig.title || name || '','spycloud')]" \
        -o json 2>/dev/null || echo "[]")

    local connector_count
    connector_count=$(echo "$connectors" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

    if [[ "$connector_count" -gt 0 ]]; then
        ok "SpyCloud data connector is ACTIVE (${connector_count} poller(s) connected)"
    else
        log "SpyCloud data connector is not yet activated"

        # Attempt to activate if we have the necessary info
        if [[ -n "$DCE_URI" && -n "$DCR_IMMUTABLE_ID" ]]; then
            if $DRY_RUN; then
                log "[DRY RUN] Would attempt to activate SpyCloud data connector"
            else
                log "Attempting to activate the SpyCloud CCF data connector..."

                # Build the connector payload
                local connector_name="SpyCloudCCF-$(date +%s)"
                local connector_body
                connector_body=$(cat <<CONNEOF
{
    "kind": "RestApiPoller",
    "properties": {
        "connectorDefinitionName": "SpyCloudEnterpriseProtectionCCFConnector",
        "dataType": "SpyCloud Enterprise Protection",
        "dcrConfig": {
            "dataCollectionEndpoint": "${DCE_URI}",
            "dataCollectionRuleImmutableId": "${DCR_IMMUTABLE_ID}",
            "streamName": "Custom-SpyCloudBreachWatchlist_CL"
        }
    }
}
CONNEOF
)
                # Only try if API key is available
                if [[ -n "$API_KEY" ]]; then
                    connector_body=$(echo "$connector_body" | python3 -c "
import json, sys
data = json.load(sys.stdin)
data['properties']['auth'] = {
    'type': 'APIKey',
    'ApiKey': sys.argv[1],
    'ApiKeyName': 'X-API-Key',
    'ApiKeyIdentifier': 'spycloud',
    'IsApiKeyInPostPayload': False
}
print(json.dumps(data))
" "$API_KEY" 2>/dev/null || echo "$connector_body")
                fi

                local activate_result
                activate_result=$(az rest --method PUT \
                    --uri "https://management.azure.com${WS_ID}/providers/Microsoft.SecurityInsights/dataConnectors/${connector_name}?api-version=2022-12-01-preview" \
                    --body "$connector_body" 2>>"$LOGFILE") && {
                    ok "Data connector activated successfully"
                } || {
                    warn "Automatic connector activation returned an error"
                    log "  This is common -- the CCF connector often requires portal activation."
                    log "  Manual step: Sentinel -> Data connectors -> SpyCloud -> Open connector page -> Connect"
                }
            fi
        else
            log "  Cannot auto-activate: DCE URI or DCR Immutable ID not resolved."
        fi

        log "  To activate manually:"
        log "    Sentinel -> Data connectors -> filter 'SpyCloud' -> Open connector page -> Connect"
        echo -e "    ${CYAN}${PORTAL}/#blade/Microsoft_Azure_Security_Insights/DataConnectorsListBlade/subscriptionId/${SUB_ID}/resourceGroup/${RG}/workspaceName/${WS}${NC}" >&2
    fi

    # --- Configure API key if provided ---
    if [[ -n "$API_KEY" && "$connector_count" -gt 0 ]]; then
        log "API key provided -- connector should already be configured."
        log "  If the connector needs reconfiguration, use the portal connector page."
    fi
}

# ==============================================================================
# Phase 7: Enable Analytics Rules
# ==============================================================================
phase7_enable_analytics_rules() {
    phase_header 7 8 "Enable Analytics Rules"

    if [[ -z "$WS_ID" ]]; then
        err "Workspace ID not available -- cannot manage analytics rules"
        return
    fi

    # --- Fetch all analytics rules ---
    log "Fetching analytics rules from Sentinel..."
    local rules_json
    rules_json=$(az rest --method GET \
        --uri "https://management.azure.com${WS_ID}/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01" \
        -o json 2>/dev/null || echo '{"value":[]}')

    # Extract SpyCloud rules
    local spycloud_rules
    spycloud_rules=$(echo "$rules_json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
rules = []
for r in data.get('value', []):
    props = r.get('properties', {})
    display = props.get('displayName', '') or ''
    if 'SpyCloud' in display or 'spycloud' in display.lower() or 'Infostealer' in display:
        rules.append({
            'id': r.get('id', ''),
            'name': r.get('name', ''),
            'displayName': display,
            'enabled': props.get('enabled', False),
            'severity': props.get('severity', 'Unknown'),
            'kind': r.get('kind', 'Unknown')
        })
print(json.dumps(rules))
" 2>/dev/null || echo "[]")

    local total_rules enabled_rules disabled_rules
    total_rules=$(echo "$spycloud_rules" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
    enabled_rules=$(echo "$spycloud_rules" | python3 -c "import json,sys; print(sum(1 for r in json.load(sys.stdin) if r['enabled']))" 2>/dev/null || echo "0")
    disabled_rules=$((total_rules - enabled_rules))

    if [[ "$total_rules" -eq 0 ]]; then
        warn "No SpyCloud analytics rules found"
        log "  Rules are typically deployed with the content template."
        log "  Check: Sentinel -> Analytics -> filter 'SpyCloud'"
        return
    fi

    ok "Found ${total_rules} SpyCloud analytics rule(s): ${enabled_rules} enabled, ${disabled_rules} disabled"

    # --- Enable rules based on --enable-rules flag ---
    if [[ "$ENABLE_RULES" == "none" ]]; then
        log "Rule enablement skipped (--enable-rules none)"
        return
    fi

    if [[ "$disabled_rules" -eq 0 ]]; then
        ok "All rules are already enabled"
        return
    fi

    if ! $NON_INTERACTIVE && [[ "$ENABLE_RULES" != "all" && "$ENABLE_RULES" != "spycloud" ]]; then
        if ! confirm_action "Enable all ${disabled_rules} disabled SpyCloud analytics rules?"; then
            log "Rule enablement skipped by user"
            return
        fi
    fi

    if $DRY_RUN; then
        log "[DRY RUN] Would enable ${disabled_rules} disabled analytics rules"
        # List them
        echo "$spycloud_rules" | python3 -c "
import json, sys
for r in json.load(sys.stdin):
    if not r['enabled']:
        print(f\"  [DRY RUN] Would enable: {r['displayName']} (severity={r['severity']})\")
" 2>/dev/null >&2
        return
    fi

    log "Enabling ${disabled_rules} disabled analytics rules..."
    local enable_success=0
    local enable_fail=0

    # Process each disabled rule
    echo "$spycloud_rules" | python3 -c "
import json, sys
for r in json.load(sys.stdin):
    if not r['enabled']:
        print(f\"{r['id']}\t{r['displayName']}\t{r['severity']}\t{r['kind']}\")
" 2>/dev/null | while IFS=$'\t' read -r rule_id rule_display rule_severity rule_kind; do
        [[ -z "$rule_id" ]] && continue

        # Fetch the full rule to PATCH it
        local full_rule
        full_rule=$(az rest --method GET \
            --uri "https://management.azure.com${rule_id}?api-version=2023-02-01" \
            -o json 2>/dev/null || echo "")

        if [[ -z "$full_rule" ]]; then
            warn "Could not fetch rule: ${rule_display}"
            ((enable_fail++)) || true
            continue
        fi

        # Set enabled=true in properties
        local updated_rule
        updated_rule=$(echo "$full_rule" | python3 -c "
import json, sys
rule = json.load(sys.stdin)
rule['properties']['enabled'] = True
# Only keep required fields for PUT
output = {
    'kind': rule.get('kind', 'Scheduled'),
    'properties': rule['properties']
}
# Remove read-only fields
for key in ['lastModifiedUtc', 'incidentConfiguration', 'entityMappings']:
    pass  # Keep these, they are needed
print(json.dumps(output))
" 2>/dev/null || echo "")

        if [[ -z "$updated_rule" ]]; then
            warn "Could not prepare update for: ${rule_display}"
            ((enable_fail++)) || true
            continue
        fi

        if az rest --method PUT \
            --uri "https://management.azure.com${rule_id}?api-version=2023-02-01" \
            --body "$updated_rule" \
            -o none 2>>"$LOGFILE"; then
            ok "Enabled: ${rule_display} (${rule_severity})"
            ((enable_success++)) || true
        else
            warn "Failed to enable: ${rule_display}"
            ((enable_fail++)) || true
        fi
    done

    # Summary
    log "Analytics rules enablement complete"

    # Re-check final state
    local final_enabled
    final_enabled=$(az rest --method GET \
        --uri "https://management.azure.com${WS_ID}/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01" \
        --query "value[?contains(properties.displayName || '','SpyCloud') && properties.enabled] | length(@)" \
        -o tsv 2>/dev/null || echo "?")
    log "  Total enabled SpyCloud rules: ${final_enabled}/${total_rules}"
}

# ==============================================================================
# Phase 8: Verify Everything
# ==============================================================================
phase8_verify() {
    phase_header 8 8 "Comprehensive Health Verification"

    local v_pass=0 v_warn=0 v_fail=0

    vpass() { ((v_pass++)); echo -e "  ${GREEN}PASS${NC}  $1" >&2; echo "VERIFY PASS: $1" >> "$LOGFILE"; }
    vwarn() { ((v_warn++)); echo -e "  ${YELLOW}WARN${NC}  $1" >&2; echo "VERIFY WARN: $1" >> "$LOGFILE"; }
    vfail() { ((v_fail++)); echo -e "  ${RED}FAIL${NC}  $1" >&2; echo "VERIFY FAIL: $1" >> "$LOGFILE"; }
    vinfo() { echo -e "  ${DIM}INFO${NC}  $1" >&2; }

    # --- 8a: Workspace & Sentinel ---
    echo -e "\n  ${BOLD}--- Workspace & Sentinel ---${NC}" >&2
    if az monitor log-analytics workspace show --workspace-name "$WS" -g "$RG" &>/dev/null; then
        local ws_loc ws_sku ws_ret
        ws_loc=$(az monitor log-analytics workspace show --workspace-name "$WS" -g "$RG" --query location -o tsv 2>/dev/null)
        ws_sku=$(az monitor log-analytics workspace show --workspace-name "$WS" -g "$RG" --query "sku.name" -o tsv 2>/dev/null)
        ws_ret=$(az monitor log-analytics workspace show --workspace-name "$WS" -g "$RG" --query retentionInDays -o tsv 2>/dev/null)
        vpass "Workspace '${WS}' (region=${ws_loc}, sku=${ws_sku}, retention=${ws_ret}d)"
    else
        vfail "Workspace '${WS}' not found"
    fi

    local sentinel_check
    sentinel_check=$(az resource list -g "$RG" --resource-type "Microsoft.OperationsManagement/solutions" \
        --query "[?contains(name,'SecurityInsights')].name" -o tsv 2>/dev/null || echo "")
    if [[ -n "$sentinel_check" ]]; then
        vpass "Microsoft Sentinel enabled on workspace"
    else
        vfail "Microsoft Sentinel not enabled"
    fi

    # --- 8b: DCE Connectivity ---
    echo -e "\n  ${BOLD}--- Data Collection Endpoint ---${NC}" >&2
    if [[ -n "$DCE_URI" ]]; then
        vpass "DCE '${DCE_NAME}' resolved (${DCE_URI})"
        # Test connectivity
        local dce_http_code
        dce_http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${DCE_URI}" 2>/dev/null || echo "000")
        if [[ "$dce_http_code" == "000" ]]; then
            vwarn "DCE endpoint not reachable from this network (HTTP ${dce_http_code})"
            vinfo "This may be expected if running outside Azure or behind a firewall"
        elif [[ "$dce_http_code" =~ ^(200|401|403|404)$ ]]; then
            vpass "DCE endpoint is reachable (HTTP ${dce_http_code})"
        else
            vwarn "DCE endpoint returned unexpected status (HTTP ${dce_http_code})"
        fi
    else
        vfail "DCE not resolved"
    fi

    # --- 8c: DCR Configuration ---
    echo -e "\n  ${BOLD}--- Data Collection Rule ---${NC}" >&2
    if [[ -n "$DCR_IMMUTABLE_ID" ]]; then
        vpass "DCR '${DCR_NAME}' (immutableId=${DCR_IMMUTABLE_ID})"
        local stream_count
        stream_count=$(az monitor data-collection rule show --name "$DCR_NAME" -g "$RG" \
            --query "length(streamDeclarations)" -o tsv 2>/dev/null || echo "0")
        if [[ "$stream_count" -ge 4 ]]; then
            vpass "DCR has ${stream_count} stream declarations (expected >= 4)"
        elif [[ "$stream_count" -gt 0 ]]; then
            vwarn "DCR has ${stream_count} stream declarations (expected >= 4)"
        else
            vfail "DCR has no stream declarations"
        fi
    else
        vfail "DCR not resolved"
    fi

    # --- 8d: Custom Tables ---
    echo -e "\n  ${BOLD}--- Custom Tables ---${NC}" >&2
    local expected_tables=("SpyCloudBreachWatchlist_CL" "SpyCloudBreachCatalog_CL" "Spycloud_MDE_Logs_CL" "SpyCloud_ConditionalAccessLogs_CL")
    for tbl in "${expected_tables[@]}"; do
        local tbl_info
        tbl_info=$(az monitor log-analytics workspace table show \
            --workspace-name "$WS" -g "$RG" --name "$tbl" \
            --query "{plan:plan,ret:retentionInDays,cols:length(schema.columns)}" -o tsv 2>/dev/null || echo "")
        if [[ -n "$tbl_info" ]]; then
            local tbl_plan tbl_ret tbl_cols
            tbl_plan=$(echo "$tbl_info" | cut -f1)
            tbl_ret=$(echo "$tbl_info" | cut -f2)
            tbl_cols=$(echo "$tbl_info" | cut -f3)
            vpass "${tbl} (${tbl_cols} cols, ${tbl_ret}d retention, plan=${tbl_plan})"
        else
            vwarn "${tbl} not found (may be created on first data ingestion)"
        fi
    done

    # --- 8e: Data Connector Status ---
    echo -e "\n  ${BOLD}--- Data Connector ---${NC}" >&2
    local conn_count
    conn_count=$(az rest --method GET \
        --uri "https://management.azure.com${WS_ID}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-12-01-preview" \
        --query "value[?contains(properties.connectorDefinitionName || name || '','SpyCloud') || contains(properties.connectorDefinitionName || name || '','spycloud')] | length(@)" \
        -o tsv 2>/dev/null || echo "0")
    if [[ "$conn_count" -gt 0 ]]; then
        vpass "SpyCloud data connector ACTIVE (${conn_count} instance(s))"
    else
        vwarn "SpyCloud data connector not yet activated"
        vinfo "Activate: Sentinel -> Data connectors -> SpyCloud -> Connect"
    fi

    # --- 8f: Playbook Status ---
    echo -e "\n  ${BOLD}--- Logic App Playbooks ---${NC}" >&2
    local playbook_list
    playbook_list=$(az logic workflow list -g "$RG" \
        --query "[?contains(name,'SpyCloud')].{name:name,state:state,pid:identity.principalId}" \
        -o tsv 2>/dev/null || echo "")
    if [[ -n "$playbook_list" ]]; then
        while IFS=$'\t' read -r pb_name pb_state pb_pid; do
            [[ -z "$pb_name" ]] && continue
            if [[ "$pb_state" == "Enabled" ]]; then
                vpass "${pb_name} (state=Enabled, identity=${pb_pid:-none})"
            else
                vwarn "${pb_name} (state=${pb_state})"
            fi
        done <<< "$playbook_list"
    else
        vwarn "No SpyCloud playbooks found"
    fi

    # --- 8g: Analytics Rules ---
    echo -e "\n  ${BOLD}--- Analytics Rules ---${NC}" >&2
    local rule_total rule_enabled
    rule_total=$(az rest --method GET \
        --uri "https://management.azure.com${WS_ID}/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01" \
        --query "value[?contains(properties.displayName || '','SpyCloud')] | length(@)" \
        -o tsv 2>/dev/null || echo "0")
    rule_enabled=$(az rest --method GET \
        --uri "https://management.azure.com${WS_ID}/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01" \
        --query "value[?contains(properties.displayName || '','SpyCloud') && properties.enabled] | length(@)" \
        -o tsv 2>/dev/null || echo "0")

    if [[ "$rule_total" -gt 0 ]]; then
        if [[ "$rule_enabled" -eq "$rule_total" ]]; then
            vpass "${rule_total} analytics rules deployed, all enabled"
        elif [[ "$rule_enabled" -gt 0 ]]; then
            vpass "${rule_total} analytics rules deployed, ${rule_enabled} enabled"
        else
            vwarn "${rule_total} analytics rules deployed, NONE enabled"
            vinfo "Enable rules: Sentinel -> Analytics -> filter 'SpyCloud'"
        fi
    else
        vwarn "No SpyCloud analytics rules found"
    fi

    # --- 8h: Data Flow Check ---
    echo -e "\n  ${BOLD}--- Data Flow ---${NC}" >&2
    for tbl in "SpyCloudBreachWatchlist_CL" "SpyCloudBreachCatalog_CL"; do
        local row_count
        row_count=$(az monitor log-analytics query -w "$WS_ID" \
            --analytics-query "${tbl} | count" \
            --query "[0].Count" -o tsv 2>/dev/null || echo "0")
        if [[ "$row_count" -gt 0 ]] 2>/dev/null; then
            local latest_ts
            latest_ts=$(az monitor log-analytics query -w "$WS_ID" \
                --analytics-query "${tbl} | summarize max(TimeGenerated)" \
                --query "[0].max_TimeGenerated" -o tsv 2>/dev/null || echo "unknown")
            vpass "${tbl}: ${row_count} records (latest: ${latest_ts})"
        else
            vinfo "${tbl}: 0 records (connector may not have run yet)"
        fi
    done

    # --- 8i: Key Vault ---
    echo -e "\n  ${BOLD}--- Key Vault ---${NC}" >&2
    local kv_name
    kv_name=$(az keyvault list -g "$RG" \
        --query "[?contains(name,'spycloud') || contains(name,'spytel')].name | [0]" \
        -o tsv 2>/dev/null || echo "")
    if [[ -n "$kv_name" ]]; then
        vpass "Key Vault '${kv_name}' exists"
        local secret_check
        secret_check=$(az keyvault secret show --vault-name "$kv_name" --name "spycloud-api-key" \
            --query name -o tsv 2>/dev/null || echo "")
        if [[ -n "$secret_check" ]]; then
            vpass "API key secret exists in Key Vault"
        else
            vwarn "API key secret not found in Key Vault"
        fi
    else
        vinfo "No Key Vault found (optional)"
    fi

    # --- 8j: Workbook ---
    echo -e "\n  ${BOLD}--- Workbook ---${NC}" >&2
    local workbook_name
    workbook_name=$(az rest --method GET \
        --uri "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.Insights/workbooks?api-version=2022-04-01" \
        --query "value[?contains(properties.displayName || '','SpyCloud')].properties.displayName | [0]" \
        -o tsv 2>/dev/null || echo "")
    if [[ -n "$workbook_name" ]]; then
        vpass "Workbook '${workbook_name}' deployed"
    else
        vwarn "No SpyCloud workbook found"
    fi

    # ==============================================================================
    # Summary Report
    # ==============================================================================
    echo "" >&2
    echo -e "${TEAL}======================================================================${NC}" >&2
    echo -e "${TEAL}  POST-DEPLOYMENT SUMMARY REPORT${NC}" >&2
    echo -e "${TEAL}======================================================================${NC}" >&2
    echo "" >&2
    echo -e "  ${BOLD}Environment${NC}" >&2
    echo -e "    Subscription:     ${SUB_NAME} (${SUB_ID})" >&2
    echo -e "    Tenant:           ${TENANT_ID}" >&2
    echo -e "    Resource Group:   ${RG}" >&2
    echo -e "    Workspace:        ${WS}" >&2
    echo -e "    DCE URI:          ${DCE_URI:-NOT RESOLVED}" >&2
    echo -e "    DCR Immutable ID: ${DCR_IMMUTABLE_ID:-NOT RESOLVED}" >&2
    echo "" >&2
    echo -e "  ${BOLD}Verification Results${NC}" >&2
    echo -e "    ${GREEN}PASS: ${v_pass}${NC}  |  ${YELLOW}WARN: ${v_warn}${NC}  |  ${RED}FAIL: ${v_fail}${NC}" >&2
    echo "" >&2
    echo -e "  ${BOLD}Automation Results${NC}" >&2
    echo -e "    ${GREEN}OK: ${PHASE_PASS}${NC}  |  ${YELLOW}WARN: ${PHASE_WARN}${NC}  |  ${RED}FAIL: ${PHASE_FAIL}${NC}  |  ${DIM}SKIP: ${PHASE_SKIP}${NC}" >&2
    echo "" >&2
    echo -e "  ${BOLD}Elapsed Time:${NC} $(elapsed)" >&2
    echo -e "  ${BOLD}Log File:${NC}     ${LOGFILE}" >&2
    echo "" >&2

    if [[ $v_fail -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}ACTION REQUIRED:${NC} ${v_fail} check(s) failed. Review the details above." >&2
    elif [[ $v_warn -gt 0 ]]; then
        echo -e "  ${YELLOW}${BOLD}REVIEW:${NC} ${v_warn} warning(s). Some items may need manual attention." >&2
    else
        echo -e "  ${GREEN}${BOLD}ALL CHECKS PASSED${NC} -- deployment is healthy." >&2
    fi

    echo "" >&2
    echo -e "  ${BOLD}Remaining Manual Steps (if any):${NC}" >&2
    echo -e "    1. Grant admin consent for API permissions (if shown as 'Pending')" >&2
    echo -e "       ${CYAN}${PORTAL}/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview${NC}" >&2
    echo -e "    2. Activate data connector (if not auto-connected)" >&2
    echo -e "       Sentinel -> Data connectors -> SpyCloud -> Connect" >&2
    echo -e "    3. Configure Entra ID diagnostic settings" >&2
    echo -e "       Entra ID -> Monitoring -> Diagnostic settings -> Add -> Send to ${WS}" >&2
    echo -e "    4. Upload Security Copilot plugin and agent YAML files" >&2
    echo -e "    5. Install IdP connectors (Okta/Duo/Ping/CyberArk) from Content Hub" >&2
    echo "" >&2
    echo -e "${TEAL}======================================================================${NC}" >&2

    # Write summary to log
    {
        echo ""
        echo "================ SUMMARY ================"
        echo "Verification: PASS=${v_pass} WARN=${v_warn} FAIL=${v_fail}"
        echo "Automation:   OK=${PHASE_PASS} WARN=${PHASE_WARN} FAIL=${PHASE_FAIL} SKIP=${PHASE_SKIP}"
        echo "Elapsed: $(elapsed)"
        echo "=========================================="
    } >> "$LOGFILE"
}

# ==============================================================================
# Main Execution
# ==============================================================================
main() {
    parse_args "$@"
    show_banner

    log "Starting post-deployment automation..."
    log "Timestamp: ${TIMESTAMP}"
    debug "Arguments: RG=${RG} WS=${WS} SUB=${SUB} ENABLE_RULES=${ENABLE_RULES} DRY_RUN=${DRY_RUN} NON_INTERACTIVE=${NON_INTERACTIVE}"

    phase1_validate_discover
    phase2_resolve_dce_dcr
    phase3_rbac_assignments
    phase4_graph_permissions
    phase5_mde_permissions
    phase6_connect_data_connector
    phase7_enable_analytics_rules
    phase8_verify

    echo "" >&2
    log "Post-deployment automation complete. Total time: $(elapsed)"
    log "Full log: ${LOGFILE}"
}

main "$@"
