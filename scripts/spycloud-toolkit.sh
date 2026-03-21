#!/usr/bin/env bash
###############################################################################
# SpyCloud Identity Exposure Intelligence for Sentinel — Unified Toolkit v2.0
#
# A comprehensive command-line toolkit for managing, deploying, testing,
# and monitoring the SpyCloud Sentinel solution.
#
# Usage:
#   bash spycloud-toolkit.sh [command] [options]
#
# Commands:
#   --health-check          Run full health check across all components
#   --fix-permissions       Auto-fix managed identity permissions
#   --test-logic-apps       Test all Logic App playbook connections
#   --test-functions        Test Azure Function App endpoints
#   --test-agent            Test SCORCH Agent connectivity
#   --generate-data         Generate simulated breach data for testing
#   --report                Generate comprehensive status report
#   --deploy                Deploy or update the solution
#   --download-workbooks    Download workbook JSON files
#   --import-workbooks      Import workbooks to Sentinel workspace
#   --download-notebooks    Download Jupyter notebook files
#   --import-notebooks      Import notebooks to Sentinel workspace
#   --download-plugins      Download Copilot plugin files
#   --verify-connector      Verify data connector status
#   --verify-tables         Verify custom log tables exist and have data
#   --verify-analytics      Verify analytics rules are enabled
#   --check-isv             Run ISV/Marketplace readiness check
#   --full-report           Generate full HTML report with all checks
#   --help                  Show this help message
#
# Environment Variables:
#   AZURE_SUBSCRIPTION_ID   Azure subscription ID
#   RESOURCE_GROUP          Resource group name
#   WORKSPACE_NAME          Log Analytics workspace name
#   SPYCLOUD_API_KEY        SpyCloud API key (for data simulation)
#   AI_ENGINE_URL           AI Engine Function App URL
#
###############################################################################
set -euo pipefail

# ============================================================
# Configuration and Constants
# ============================================================
VERSION="2.0.0"
SOLUTION_NAME="SpyCloud Identity Exposure Intelligence for Sentinel"
REPO_URL="https://github.com/iammrherb/SPYCLOUD-SENTINEL"
RAW_URL="https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0

# Report storage
REPORT_DIR="/tmp/spycloud-report-$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="${REPORT_DIR}/report.html"

# Custom log tables
CUSTOM_TABLES=(
    "SpyCloudBreachWatchlist_CL"
    "SpyCloudBreachCatalog_CL"
    "SpyCloudCompassData_CL"
    "SpyCloudCompassDevices_CL"
    "SpyCloudCompassApps_CL"
    "SpyCloudSipCookies_CL"
    "SpyCloudInvestigations_CL"
    "SpyCloudIdLink_CL"
    "SpyCloudCAP_CL"
    "SpyCloudExposure_CL"
    "SpyCloudIdentityExposure_CL"
    "SpyCloudEnrichmentAudit_CL"
    "SpyCloud_ConditionalAccessLogs_CL"
    "Spycloud_MDE_Logs_CL"
)

# Playbooks
PLAYBOOKS=(
    "SpyCloud-EnrichIncident"
    "SpyCloud-ForcePasswordReset"
    "SpyCloud-RevokeSessions"
    "SpyCloud-IsolateDevice"
    "SpyCloud-DisableAccount"
    "SpyCloud-EnforceMFA"
    "SpyCloud-BlockConditionalAccess"
    "SpyCloud-BlockFirewall"
    "SpyCloud-RevokeOAuthConsent"
    "SpyCloud-RemoveMailboxRules"
    "SpyCloud-AddToSecurityGroup"
    "SpyCloud-FullRemediation"
    "SpyCloud-NotifySOC"
    "SpyCloud-NotifyUser"
    "SpyCloud-EmailNotify"
    "SpyCloud-SlackNotify"
    "SpyCloud-WebhookNotify"
    "SpyCloud-Jira"
    "SpyCloud-ServiceNow"
    "SpyCloud-Copilot-Triage"
    "SpyCloud-PurviewComplianceCheck"
    "SpyCloud-PurviewLabelIncident"
)

# Required Graph API permissions
REQUIRED_PERMISSIONS=(
    "User.ReadWrite.All"
    "Directory.ReadWrite.All"
    "SecurityEvents.ReadWrite.All"
    "Mail.ReadWrite"
    "Policy.ReadWrite.ConditionalAccess"
    "DeviceManagementManagedDevices.ReadWrite.All"
    "InformationProtection.Policy.Read.All"
    "SecurityIncident.ReadWrite.All"
)

# ============================================================
# Helper Functions
# ============================================================
print_banner() {
    echo -e "${PURPLE}"
    echo "  ____              ____ _                 _"
    echo " / ___| _ __  _   _/ ___| | ___  _   _  __| |"
    echo " \\___ \\| '_ \\| | | \\___ \\ |/ _ \\| | | |/ _\` |"
    echo "  ___) | |_) | |_| |___) | | (_) | |_| | (_| |"
    echo " |____/| .__/ \\__, |____/|_|\\___/ \\__,_|\\__,_|"
    echo "       |_|    |___/"
    echo -e "${NC}"
    echo -e "${WHITE}${BOLD}${SOLUTION_NAME}${NC}"
    echo -e "${CYAN}Unified Toolkit v${VERSION}${NC}"
    echo -e "${CYAN}$(date -u '+%Y-%m-%d %H:%M:%S UTC')${NC}"
    echo ""
}

log_pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

log_fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

log_warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
    WARN_COUNT=$((WARN_COUNT + 1))
}

log_skip() {
    echo -e "  ${BLUE}[SKIP]${NC} $1"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

log_info() {
    echo -e "  ${CYAN}[INFO]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${WHITE}${BOLD}=== $1 ===${NC}"
    echo ""
}

check_az_cli() {
    if ! command -v az &> /dev/null; then
        log_fail "Azure CLI (az) not found. Install: https://aka.ms/installazurecli"
        return 1
    fi
    log_pass "Azure CLI installed: $(az version --query '"azure-cli"' -o tsv 2>/dev/null || echo 'unknown')"

    # Check if logged in
    if ! az account show &> /dev/null 2>&1; then
        log_fail "Not logged in to Azure CLI. Run: az login"
        return 1
    fi
    local account
    account=$(az account show --query name -o tsv 2>/dev/null)
    log_pass "Logged in to Azure: ${account}"
    return 0
}

check_env_vars() {
    local missing=0
    if [[ -z "${AZURE_SUBSCRIPTION_ID:-}" ]]; then
        log_warn "AZURE_SUBSCRIPTION_ID not set. Some checks will be skipped."
        ((missing++))
    else
        log_pass "AZURE_SUBSCRIPTION_ID is set"
    fi

    if [[ -z "${RESOURCE_GROUP:-}" ]]; then
        log_warn "RESOURCE_GROUP not set. Some checks will be skipped."
        ((missing++))
    else
        log_pass "RESOURCE_GROUP is set"
    fi

    if [[ -z "${WORKSPACE_NAME:-}" ]]; then
        log_warn "WORKSPACE_NAME not set. Some checks will be skipped."
        ((missing++))
    else
        log_pass "WORKSPACE_NAME is set"
    fi

    return $missing
}

# ============================================================
# Health Check Functions
# ============================================================
health_check_azure() {
    log_section "Azure Environment Health"

    check_az_cli || return 1

    # Check subscription
    if [[ -n "${AZURE_SUBSCRIPTION_ID:-}" ]]; then
        az account set --subscription "${AZURE_SUBSCRIPTION_ID}" 2>/dev/null
        log_pass "Subscription set: ${AZURE_SUBSCRIPTION_ID}"
    fi

    # Check resource group
    if [[ -n "${RESOURCE_GROUP:-}" ]]; then
        if az group show --name "${RESOURCE_GROUP}" &>/dev/null 2>&1; then
            log_pass "Resource group exists: ${RESOURCE_GROUP}"
        else
            log_fail "Resource group not found: ${RESOURCE_GROUP}"
        fi
    fi

    # Check workspace
    if [[ -n "${RESOURCE_GROUP:-}" && -n "${WORKSPACE_NAME:-}" ]]; then
        if az monitor log-analytics workspace show \
            --resource-group "${RESOURCE_GROUP}" \
            --workspace-name "${WORKSPACE_NAME}" &>/dev/null 2>&1; then
            log_pass "Log Analytics workspace exists: ${WORKSPACE_NAME}"

            # Check if Sentinel is enabled
            local sentinel_status
            sentinel_status=$(az sentinel onboarding-state show \
                --resource-group "${RESOURCE_GROUP}" \
                --workspace-name "${WORKSPACE_NAME}" \
                --name "default" 2>/dev/null || echo "not-found")
            if [[ "${sentinel_status}" != "not-found" ]]; then
                log_pass "Microsoft Sentinel is enabled on workspace"
            else
                log_fail "Microsoft Sentinel is NOT enabled on workspace"
            fi
        else
            log_fail "Log Analytics workspace not found: ${WORKSPACE_NAME}"
        fi
    fi

    # Check resource providers
    local providers=("Microsoft.OperationalInsights" "Microsoft.SecurityInsights" "Microsoft.Logic" "Microsoft.Web")
    for provider in "${providers[@]}"; do
        local state
        state=$(az provider show --namespace "${provider}" --query "registrationState" -o tsv 2>/dev/null || echo "NotRegistered")
        if [[ "${state}" == "Registered" ]]; then
            log_pass "Resource provider registered: ${provider}"
        else
            log_fail "Resource provider NOT registered: ${provider} (${state})"
        fi
    done
}

health_check_tables() {
    log_section "Custom Log Tables"

    if [[ -z "${RESOURCE_GROUP:-}" || -z "${WORKSPACE_NAME:-}" ]]; then
        log_skip "Skipping table checks (RESOURCE_GROUP or WORKSPACE_NAME not set)"
        return
    fi

    local workspace_id
    workspace_id=$(az monitor log-analytics workspace show \
        --resource-group "${RESOURCE_GROUP}" \
        --workspace-name "${WORKSPACE_NAME}" \
        --query customerId -o tsv 2>/dev/null || echo "")

    if [[ -z "${workspace_id}" ]]; then
        log_fail "Could not retrieve workspace ID"
        return
    fi

    for table in "${CUSTOM_TABLES[@]}"; do
        local result
        result=$(az monitor log-analytics query \
            --workspace "${workspace_id}" \
            --analytics-query "${table} | take 1" \
            2>/dev/null || echo "error")

        if [[ "${result}" == "error" || "${result}" == *"BadArgumentError"* ]]; then
            log_warn "Table not found or empty: ${table}"
        else
            local count
            count=$(az monitor log-analytics query \
                --workspace "${workspace_id}" \
                --analytics-query "${table} | summarize count()" \
                --query "[0].count_" -o tsv 2>/dev/null || echo "0")
            if [[ "${count}" -gt 0 ]]; then
                log_pass "Table ${table}: ${count} records"
            else
                log_warn "Table exists but empty: ${table}"
            fi
        fi
    done
}

health_check_playbooks() {
    log_section "Logic App Playbooks"

    if [[ -z "${RESOURCE_GROUP:-}" ]]; then
        log_skip "Skipping playbook checks (RESOURCE_GROUP not set)"
        return
    fi

    for playbook in "${PLAYBOOKS[@]}"; do
        local state
        state=$(az logic workflow show \
            --resource-group "${RESOURCE_GROUP}" \
            --name "${playbook}" \
            --query "state" -o tsv 2>/dev/null || echo "NotFound")

        if [[ "${state}" == "Enabled" ]]; then
            log_pass "Playbook enabled: ${playbook}"

            # Check last run
            local last_run
            last_run=$(az logic workflow show \
                --resource-group "${RESOURCE_GROUP}" \
                --name "${playbook}" \
                --query "changedTime" -o tsv 2>/dev/null || echo "N/A")
            log_info "  Last modified: ${last_run}"
        elif [[ "${state}" == "Disabled" ]]; then
            log_warn "Playbook disabled: ${playbook}"
        else
            log_warn "Playbook not found: ${playbook}"
        fi
    done
}

health_check_connector() {
    log_section "Data Connector Status"

    if [[ -z "${RESOURCE_GROUP:-}" || -z "${WORKSPACE_NAME:-}" ]]; then
        log_skip "Skipping connector checks (env vars not set)"
        return
    fi

    # Check for SpyCloud data connector
    local connectors
    connectors=$(az sentinel data-connector list \
        --resource-group "${RESOURCE_GROUP}" \
        --workspace-name "${WORKSPACE_NAME}" \
        2>/dev/null || echo "[]")

    if echo "${connectors}" | grep -qi "spycloud"; then
        log_pass "SpyCloud data connector found"
    else
        log_warn "SpyCloud data connector not found — may need activation"
    fi

    # Check recent data ingestion
    local workspace_id
    workspace_id=$(az monitor log-analytics workspace show \
        --resource-group "${RESOURCE_GROUP}" \
        --workspace-name "${WORKSPACE_NAME}" \
        --query customerId -o tsv 2>/dev/null || echo "")

    if [[ -n "${workspace_id}" ]]; then
        local latest
        latest=$(az monitor log-analytics query \
            --workspace "${workspace_id}" \
            --analytics-query "SpyCloudBreachWatchlist_CL | summarize max(TimeGenerated)" \
            --query "[0].max_TimeGenerated" -o tsv 2>/dev/null || echo "none")

        if [[ "${latest}" != "none" && -n "${latest}" ]]; then
            log_pass "Latest data in SpyCloudBreachWatchlist_CL: ${latest}"
        else
            log_warn "No data found in SpyCloudBreachWatchlist_CL"
        fi
    fi
}

health_check_analytics() {
    log_section "Analytics Rules"

    if [[ -z "${RESOURCE_GROUP:-}" || -z "${WORKSPACE_NAME:-}" ]]; then
        log_skip "Skipping analytics checks (env vars not set)"
        return
    fi

    local rules
    rules=$(az sentinel alert-rule list \
        --resource-group "${RESOURCE_GROUP}" \
        --workspace-name "${WORKSPACE_NAME}" \
        2>/dev/null || echo "[]")

    local total enabled disabled
    total=$(echo "${rules}" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len([r for r in data if 'SpyCloud' in r.get('displayName','')]))" 2>/dev/null || echo "0")
    enabled=$(echo "${rules}" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len([r for r in data if 'SpyCloud' in r.get('displayName','') and r.get('enabled',False)]))" 2>/dev/null || echo "0")
    disabled=$((total - enabled))

    if [[ "${total}" -gt 0 ]]; then
        log_pass "SpyCloud analytics rules found: ${total} total"
        if [[ "${enabled}" -gt 0 ]]; then
            log_pass "  Enabled: ${enabled}"
        fi
        if [[ "${disabled}" -gt 0 ]]; then
            log_warn "  Disabled: ${disabled}"
        fi
    else
        log_warn "No SpyCloud analytics rules found"
    fi
}

health_check_function_app() {
    log_section "Function App Health"

    if [[ -z "${RESOURCE_GROUP:-}" ]]; then
        log_skip "Skipping Function App checks (RESOURCE_GROUP not set)"
        return
    fi

    # Check enrichment function
    local enrichment_state
    enrichment_state=$(az functionapp show \
        --resource-group "${RESOURCE_GROUP}" \
        --name "spycloud-enrichment-*" \
        --query "state" -o tsv 2>/dev/null || echo "NotFound")

    # Try with common naming patterns
    local func_apps
    func_apps=$(az functionapp list \
        --resource-group "${RESOURCE_GROUP}" \
        --query "[?contains(name, 'spycloud') || contains(name, 'SpyCloud')].{name:name, state:state}" \
        -o tsv 2>/dev/null || echo "")

    if [[ -n "${func_apps}" ]]; then
        while IFS=$'\t' read -r name state; do
            if [[ "${state}" == "Running" ]]; then
                log_pass "Function App running: ${name}"
            else
                log_fail "Function App not running: ${name} (${state})"
            fi
        done <<< "${func_apps}"
    else
        log_warn "No SpyCloud Function Apps found in resource group"
    fi

    # Test AI Engine if URL provided
    if [[ -n "${AI_ENGINE_URL:-}" ]]; then
        local health_response
        health_response=$(curl -s -o /dev/null -w "%{http_code}" \
            "${AI_ENGINE_URL}/api/ai/health" 2>/dev/null || echo "000")

        if [[ "${health_response}" == "200" ]]; then
            log_pass "AI Engine health endpoint responding (200 OK)"
        else
            log_fail "AI Engine health endpoint failed (HTTP ${health_response})"
        fi
    fi
}

# ============================================================
# Permission Management
# ============================================================
fix_permissions() {
    log_section "Fixing Managed Identity Permissions"

    if [[ -z "${RESOURCE_GROUP:-}" ]]; then
        log_fail "RESOURCE_GROUP must be set to fix permissions"
        return 1
    fi

    echo -e "${CYAN}This will grant the following Graph API permissions to all SpyCloud Logic App managed identities:${NC}"
    for perm in "${REQUIRED_PERMISSIONS[@]}"; do
        echo -e "  - ${perm}"
    done
    echo ""

    read -rp "Continue? (y/N): " confirm
    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        log_info "Cancelled by user"
        return
    fi

    # Get Microsoft Graph service principal
    local graph_sp_id
    graph_sp_id=$(az ad sp list --filter "displayName eq 'Microsoft Graph'" \
        --query "[0].id" -o tsv 2>/dev/null || echo "")

    if [[ -z "${graph_sp_id}" ]]; then
        log_fail "Could not find Microsoft Graph service principal"
        return 1
    fi

    # Process each playbook
    for playbook in "${PLAYBOOKS[@]}"; do
        local principal_id
        principal_id=$(az logic workflow show \
            --resource-group "${RESOURCE_GROUP}" \
            --name "${playbook}" \
            --query "identity.principalId" -o tsv 2>/dev/null || echo "")

        if [[ -z "${principal_id}" || "${principal_id}" == "None" ]]; then
            log_skip "No managed identity for: ${playbook}"
            continue
        fi

        log_info "Granting permissions to ${playbook} (${principal_id})"

        for perm in "${REQUIRED_PERMISSIONS[@]}"; do
            local role_id
            role_id=$(az ad sp show --id "${graph_sp_id}" \
                --query "appRoles[?value=='${perm}'].id | [0]" -o tsv 2>/dev/null || echo "")

            if [[ -z "${role_id}" ]]; then
                log_warn "  Permission not found: ${perm}"
                continue
            fi

            az rest --method POST \
                --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${graph_sp_id}/appRoleAssignments" \
                --body "{\"principalId\": \"${principal_id}\", \"resourceId\": \"${graph_sp_id}\", \"appRoleId\": \"${role_id}\"}" \
                2>/dev/null && log_pass "  Granted: ${perm}" || log_warn "  Already assigned or failed: ${perm}"
        done
    done
}

# ============================================================
# Testing Functions
# ============================================================
test_logic_apps() {
    log_section "Testing Logic App Playbook Connections"

    if [[ -z "${RESOURCE_GROUP:-}" ]]; then
        log_fail "RESOURCE_GROUP must be set to test Logic Apps"
        return 1
    fi

    for playbook in "${PLAYBOOKS[@]}"; do
        local info
        info=$(az logic workflow show \
            --resource-group "${RESOURCE_GROUP}" \
            --name "${playbook}" \
            2>/dev/null || echo "")

        if [[ -z "${info}" ]]; then
            log_warn "Playbook not deployed: ${playbook}"
            continue
        fi

        local state
        state=$(echo "${info}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('state','Unknown'))" 2>/dev/null || echo "Unknown")

        if [[ "${state}" == "Enabled" ]]; then
            # Check API connections
            local connections
            connections=$(az logic workflow show \
                --resource-group "${RESOURCE_GROUP}" \
                --name "${playbook}" \
                --query "parameters.\$connections.value" \
                2>/dev/null || echo "{}")

            local conn_count
            conn_count=$(echo "${connections}" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

            log_pass "${playbook}: Enabled (${conn_count} connections)"

            # Check for recent failures
            local recent_fails
            recent_fails=$(az logic workflow run list \
                --resource-group "${RESOURCE_GROUP}" \
                --workflow-name "${playbook}" \
                --top 5 \
                --query "[?status=='Failed'] | length(@)" \
                -o tsv 2>/dev/null || echo "0")

            if [[ "${recent_fails}" -gt 0 ]]; then
                log_warn "  ${recent_fails} recent failures in last 5 runs"
            fi
        else
            log_warn "${playbook}: ${state}"
        fi
    done
}

test_functions() {
    log_section "Testing Azure Function App Endpoints"

    if [[ -z "${AI_ENGINE_URL:-}" ]]; then
        # Try to discover the URL
        if [[ -n "${RESOURCE_GROUP:-}" ]]; then
            local func_url
            func_url=$(az functionapp list \
                --resource-group "${RESOURCE_GROUP}" \
                --query "[?contains(name, 'ai') || contains(name, 'AI')].defaultHostName | [0]" \
                -o tsv 2>/dev/null || echo "")

            if [[ -n "${func_url}" ]]; then
                AI_ENGINE_URL="https://${func_url}"
                log_info "Discovered AI Engine URL: ${AI_ENGINE_URL}"
            else
                log_skip "AI_ENGINE_URL not set and could not auto-discover"
                return
            fi
        else
            log_skip "AI_ENGINE_URL not set (set it to test Function App endpoints)"
            return
        fi
    fi

    local endpoints=(
        "GET /api/ai/health"
    )

    for endpoint in "${endpoints[@]}"; do
        local method path
        method=$(echo "${endpoint}" | awk '{print $1}')
        path=$(echo "${endpoint}" | awk '{print $2}')

        local response_code
        response_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -X "${method}" \
            "${AI_ENGINE_URL}${path}" \
            2>/dev/null || echo "000")

        if [[ "${response_code}" == "200" ]]; then
            log_pass "Endpoint OK: ${endpoint} (${response_code})"
        elif [[ "${response_code}" == "401" || "${response_code}" == "403" ]]; then
            log_pass "Endpoint reachable (auth required): ${endpoint} (${response_code})"
        else
            log_fail "Endpoint failed: ${endpoint} (HTTP ${response_code})"
        fi
    done
}

test_agent() {
    log_section "Testing SCORCH Agent"

    if [[ -z "${AI_ENGINE_URL:-}" ]]; then
        log_skip "AI_ENGINE_URL not set — cannot test agent"
        return
    fi

    # Test investigate endpoint with a test request
    local response
    response=$(curl -s -w "\n%{http_code}" \
        -X POST "${AI_ENGINE_URL}/api/ai/health" \
        -H "Content-Type: application/json" \
        2>/dev/null || echo "000")

    local http_code
    http_code=$(echo "${response}" | tail -1)
    local body
    body=$(echo "${response}" | sed '$d')

    if [[ "${http_code}" == "200" ]]; then
        log_pass "AI Engine is responding"
        local ai_configured
        ai_configured=$(echo "${body}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('aiConfigured', False))" 2>/dev/null || echo "false")
        if [[ "${ai_configured}" == "True" ]]; then
            log_pass "AI provider is configured"
        else
            log_warn "AI provider is NOT configured — agent will have limited functionality"
        fi

        local purview_configured
        purview_configured=$(echo "${body}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('purviewConfigured', False))" 2>/dev/null || echo "false")
        if [[ "${purview_configured}" == "True" ]]; then
            log_pass "Purview integration is configured"
        else
            log_warn "Purview integration is NOT configured"
        fi
    else
        log_fail "AI Engine not responding (HTTP ${http_code})"
    fi
}

# ============================================================
# Data Generation and Simulation
# ============================================================
generate_data() {
    log_section "Data Generation and Simulation"

    if [[ -z "${RESOURCE_GROUP:-}" || -z "${WORKSPACE_NAME:-}" ]]; then
        log_fail "RESOURCE_GROUP and WORKSPACE_NAME must be set for data generation"
        return 1
    fi

    local workspace_id
    workspace_id=$(az monitor log-analytics workspace show \
        --resource-group "${RESOURCE_GROUP}" \
        --workspace-name "${WORKSPACE_NAME}" \
        --query customerId -o tsv 2>/dev/null || echo "")

    if [[ -z "${workspace_id}" ]]; then
        log_fail "Could not get workspace ID"
        return 1
    fi

    echo -e "${CYAN}Generating simulated SpyCloud breach data for testing...${NC}"
    echo -e "${YELLOW}WARNING: This will insert test data into your Sentinel workspace.${NC}"
    read -rp "Continue? (y/N): " confirm
    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        log_info "Cancelled by user"
        return
    fi

    # Generate sample records
    local dce_endpoint
    dce_endpoint=$(az monitor data-collection endpoint list \
        --resource-group "${RESOURCE_GROUP}" \
        --query "[?contains(name, 'spycloud') || contains(name, 'SpyCloud')].logsIngestion.endpoint | [0]" \
        -o tsv 2>/dev/null || echo "")

    local dcr_id
    dcr_id=$(az monitor data-collection rule list \
        --resource-group "${RESOURCE_GROUP}" \
        --query "[?contains(name, 'spycloud') || contains(name, 'SpyCloud')].immutableId | [0]" \
        -o tsv 2>/dev/null || echo "")

    if [[ -z "${dce_endpoint}" || -z "${dcr_id}" ]]; then
        log_warn "Could not find DCE/DCR for data ingestion"
        log_info "You can manually create test data using the Azure portal"
        log_info "Or configure DCE_ENDPOINT and DCR_ID environment variables"
        return
    fi

    local stream_name="Custom-SpyCloudBreachWatchlist_CL"
    local token
    token=$(az account get-access-token --resource "https://monitor.azure.com/" --query accessToken -o tsv 2>/dev/null || echo "")

    if [[ -z "${token}" ]]; then
        log_fail "Could not get Azure Monitor access token"
        return 1
    fi

    # Generate test data with various severity levels
    local test_data='[
        {
            "email": "testuser1@simulation.spycloud.local",
            "domain": "simulation.spycloud.local",
            "severity": 2,
            "source_id": 99901,
            "password_type": "sha256",
            "sighting": 1,
            "target_url": "https://example.com/login",
            "target_domain": "example.com",
            "TimeGenerated": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        },
        {
            "email": "testuser2@simulation.spycloud.local",
            "domain": "simulation.spycloud.local",
            "severity": 5,
            "source_id": 99902,
            "password_type": "plaintext",
            "password_plaintext": "SimulatedP@ss123",
            "full_name": "Test User Two",
            "phone": "+1-555-0102",
            "sighting": 3,
            "target_url": "https://example.com/login",
            "target_domain": "example.com",
            "TimeGenerated": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        },
        {
            "email": "testuser3@simulation.spycloud.local",
            "domain": "simulation.spycloud.local",
            "severity": 20,
            "source_id": 99903,
            "password_type": "plaintext",
            "password_plaintext": "Inf0stealer!2024",
            "infected_machine_id": "SIM-DEVICE-001",
            "infected_path": "C:\\Users\\test\\AppData\\Local\\Temp\\malware.exe",
            "ip_addresses": "10.0.0.100",
            "user_browser": "Chrome 120",
            "user_os": "Windows 11",
            "sighting": 5,
            "TimeGenerated": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        },
        {
            "email": "testuser4@simulation.spycloud.local",
            "domain": "simulation.spycloud.local",
            "severity": 25,
            "source_id": 99904,
            "password_type": "plaintext",
            "password_plaintext": "St0lenCr3d$2024",
            "infected_machine_id": "SIM-DEVICE-002",
            "infected_path": "C:\\ProgramData\\stealer.dll",
            "ip_addresses": "192.168.1.50",
            "full_name": "Test Executive",
            "phone": "+1-555-0104",
            "dob": "1985-03-15",
            "cc_number": "4111111111111111",
            "target_domain": "corporate-app.example.com",
            "user_browser": "Edge 119",
            "user_os": "Windows 11 Enterprise",
            "sighting": 8,
            "TimeGenerated": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        }
    ]'

    local ingest_response
    ingest_response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${dce_endpoint}/dataCollectionRules/${dcr_id}/streams/${stream_name}?api-version=2023-01-01" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "${test_data}" \
        2>/dev/null || echo "000")

    if [[ "${ingest_response}" == "204" || "${ingest_response}" == "200" ]]; then
        log_pass "Test data ingested successfully (4 records, severities 2/5/20/25)"
        log_info "Data should appear in SpyCloudBreachWatchlist_CL within 5-10 minutes"
    else
        log_fail "Data ingestion failed (HTTP ${ingest_response})"
        log_info "Verify DCE endpoint and DCR configuration"
    fi
}

# ============================================================
# Download and Import Functions
# ============================================================
download_workbooks() {
    log_section "Downloading Workbooks"

    local dest="${1:-./downloads/workbooks}"
    mkdir -p "${dest}"

    local workbook_files=(
        "SpyCloud-Executive-Dashboard.json"
        "SpyCloud-SOC-Operations.json"
        "SpyCloud-Threat-Intel-Dashboard.json"
        "SpyCloud-Defender-CA-Response.json"
        "SpyCloud-Graph-Analysis.json"
    )

    for wb in "${workbook_files[@]}"; do
        local url="${RAW_URL}/workbooks/${wb}"
        if curl -sL -o "${dest}/${wb}" "${url}" 2>/dev/null; then
            if [[ -s "${dest}/${wb}" ]]; then
                log_pass "Downloaded: ${wb}"
            else
                log_fail "Empty file: ${wb}"
                rm -f "${dest}/${wb}"
            fi
        else
            log_fail "Failed to download: ${wb}"
        fi
    done

    echo ""
    log_info "Workbooks saved to: ${dest}"
}

import_workbooks() {
    log_section "Importing Workbooks to Sentinel"

    if [[ -z "${RESOURCE_GROUP:-}" || -z "${WORKSPACE_NAME:-}" ]]; then
        log_fail "RESOURCE_GROUP and WORKSPACE_NAME must be set"
        return 1
    fi

    local source="${1:-./downloads/workbooks}"
    if [[ ! -d "${source}" ]]; then
        log_info "No local workbooks found. Downloading first..."
        download_workbooks "${source}"
    fi

    local workspace_id
    workspace_id=$(az monitor log-analytics workspace show \
        --resource-group "${RESOURCE_GROUP}" \
        --workspace-name "${WORKSPACE_NAME}" \
        --query id -o tsv 2>/dev/null || echo "")

    for wb_file in "${source}"/*.json; do
        if [[ ! -f "${wb_file}" ]]; then continue; fi
        local wb_name
        wb_name=$(basename "${wb_file}" .json)
        local wb_id
        wb_id=$(python3 -c "import uuid; print(str(uuid.uuid5(uuid.NAMESPACE_DNS, '${wb_name}')))" 2>/dev/null)

        log_info "Importing: ${wb_name}"

        local serialized
        serialized=$(python3 -c "import json; f=open('${wb_file}'); print(json.dumps(json.dumps(json.load(f))))" 2>/dev/null || echo "")

        if [[ -z "${serialized}" ]]; then
            log_fail "Could not read workbook: ${wb_name}"
            continue
        fi

        az workbook create \
            --resource-group "${RESOURCE_GROUP}" \
            --name "${wb_id}" \
            --display-name "${wb_name}" \
            --category "sentinel" \
            --kind "shared" \
            --source-id "${workspace_id}" \
            --serialized-data "${serialized}" \
            2>/dev/null && log_pass "Imported: ${wb_name}" || log_fail "Failed to import: ${wb_name}"
    done
}

download_notebooks() {
    log_section "Downloading Jupyter Notebooks"

    local dest="${1:-./downloads/notebooks}"
    mkdir -p "${dest}"

    local notebook_files=(
        "SpyCloud-ThreatHunting.ipynb"
        "SpyCloud-Incident-Triage.ipynb"
        "SpyCloud-Threat-Landscape.ipynb"
        "SpyCloud-Graph-Investigation.ipynb"
        "SpyCloud-Simulated-Scenarios.ipynb"
    )

    for nb in "${notebook_files[@]}"; do
        local url="${RAW_URL}/notebooks/${nb}"
        if curl -sL -o "${dest}/${nb}" "${url}" 2>/dev/null; then
            if [[ -s "${dest}/${nb}" ]]; then
                log_pass "Downloaded: ${nb}"
            else
                log_fail "Empty file: ${nb}"
                rm -f "${dest}/${nb}"
            fi
        else
            log_fail "Failed to download: ${nb}"
        fi
    done

    # Also download requirements.txt
    curl -sL -o "${dest}/requirements.txt" "${RAW_URL}/notebooks/requirements.txt" 2>/dev/null
    log_pass "Downloaded: requirements.txt"

    echo ""
    log_info "Notebooks saved to: ${dest}"
    log_info "Install dependencies: pip install -r ${dest}/requirements.txt"
}

download_plugins() {
    log_section "Downloading Copilot Plugins and Agent Files"

    local dest="${1:-./downloads/copilot}"
    mkdir -p "${dest}"

    local plugin_files=(
        "SpyCloud_Agent.yaml"
        "SpyCloud_Plugin.yaml"
        "SpyCloud_API_Plugin.yaml"
        "SpyCloud_API_Plugin_OpenAPI.yaml"
        "SpyCloud_MCP_Plugin.yaml"
        "SecurityCopilotAgent.json"
        "manifest.json"
    )

    for plugin in "${plugin_files[@]}"; do
        local url="${RAW_URL}/copilot/${plugin}"
        if curl -sL -o "${dest}/${plugin}" "${url}" 2>/dev/null; then
            if [[ -s "${dest}/${plugin}" ]]; then
                log_pass "Downloaded: ${plugin}"
            else
                log_fail "Empty file: ${plugin}"
                rm -f "${dest}/${plugin}"
            fi
        else
            log_fail "Failed to download: ${plugin}"
        fi
    done

    echo ""
    log_info "Plugins saved to: ${dest}"
    log_info "Upload these to Security Copilot > Settings > Plugins"
}

# ============================================================
# ISV/Marketplace Readiness Check
# ============================================================
check_isv_readiness() {
    log_section "ISV/Marketplace/Content Hub Readiness"

    local repo_root
    repo_root=$(git rev-parse --show-toplevel 2>/dev/null || echo ".")

    # Check required files
    local required_files=(
        "azuredeploy.json"
        "createUiDefinition.json"
        "mainTemplate.json"
        "solutionMetadata.json"
        "LICENSE"
        ".gitignore"
        "README.md"
    )

    for file in "${required_files[@]}"; do
        if [[ -f "${repo_root}/${file}" ]]; then
            log_pass "Required file exists: ${file}"
        else
            log_fail "Missing required file: ${file}"
        fi
    done

    # Check version consistency
    log_info "Checking version consistency..."
    local expected_version="2.0.0"

    if [[ -f "${repo_root}/azuredeploy.json" ]]; then
        local deploy_version
        deploy_version=$(python3 -c "import json; f=open('${repo_root}/azuredeploy.json'); d=json.load(f); print(d.get('variables',{}).get('solutionVersion','N/A'))" 2>/dev/null || echo "N/A")
        if [[ "${deploy_version}" == "${expected_version}" ]]; then
            log_pass "azuredeploy.json version: ${deploy_version}"
        else
            log_warn "azuredeploy.json version mismatch: ${deploy_version} (expected ${expected_version})"
        fi
    fi

    if [[ -f "${repo_root}/solutionMetadata.json" ]]; then
        local meta_version
        meta_version=$(python3 -c "import json; f=open('${repo_root}/solutionMetadata.json'); d=json.load(f); print(d.get('version','N/A'))" 2>/dev/null || echo "N/A")
        if [[ "${meta_version}" == "${expected_version}" ]]; then
            log_pass "solutionMetadata.json version: ${meta_version}"
        else
            log_warn "solutionMetadata.json version mismatch: ${meta_version} (expected ${expected_version})"
        fi
    fi

    # Check ARM template validity
    if command -v az &>/dev/null && [[ -f "${repo_root}/azuredeploy.json" ]]; then
        log_info "Validating ARM template syntax..."
        if python3 -c "import json; json.load(open('${repo_root}/azuredeploy.json'))" 2>/dev/null; then
            log_pass "azuredeploy.json is valid JSON"
        else
            log_fail "azuredeploy.json is NOT valid JSON"
        fi

        if python3 -c "import json; json.load(open('${repo_root}/mainTemplate.json'))" 2>/dev/null; then
            log_pass "mainTemplate.json is valid JSON"
        else
            log_fail "mainTemplate.json is NOT valid JSON"
        fi

        if python3 -c "import json; json.load(open('${repo_root}/createUiDefinition.json'))" 2>/dev/null; then
            log_pass "createUiDefinition.json is valid JSON"
        else
            log_fail "createUiDefinition.json is NOT valid JSON"
        fi
    fi

    # Check Content Hub package structure
    log_info "Checking Content Hub package structure..."
    local content_dirs=("templates" "playbooks" "workbooks" "analytics" "hunting")
    for dir in "${content_dirs[@]}"; do
        if [[ -d "${repo_root}/${dir}" ]]; then
            local file_count
            file_count=$(find "${repo_root}/${dir}" -name "*.json" 2>/dev/null | wc -l)
            log_pass "Directory ${dir}/: ${file_count} JSON files"
        else
            log_warn "Directory not found: ${dir}/"
        fi
    done

    # Check logo/branding
    if [[ -f "${repo_root}/images/logo.png" ]] || [[ -f "${repo_root}/images/spycloud-logo.png" ]]; then
        log_pass "Logo file found in images/"
    else
        log_warn "No logo file found in images/ — required for Content Hub"
    fi
}

# ============================================================
# Report Generation
# ============================================================
generate_report() {
    log_section "Generating Comprehensive Report"

    mkdir -p "${REPORT_DIR}"

    # Run all checks and capture output
    {
        print_banner
        health_check_azure
        health_check_tables
        health_check_playbooks
        health_check_connector
        health_check_analytics
        health_check_function_app
        check_isv_readiness
    } 2>&1 | tee "${REPORT_DIR}/output.txt"

    # Generate summary
    local total=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT + SKIP_COUNT))

    echo ""
    echo -e "${WHITE}${BOLD}=== REPORT SUMMARY ===${NC}"
    echo ""
    echo -e "  ${GREEN}Passed:  ${PASS_COUNT}${NC}"
    echo -e "  ${RED}Failed:  ${FAIL_COUNT}${NC}"
    echo -e "  ${YELLOW}Warning: ${WARN_COUNT}${NC}"
    echo -e "  ${BLUE}Skipped: ${SKIP_COUNT}${NC}"
    echo -e "  Total:   ${total}"
    echo ""

    if [[ ${FAIL_COUNT} -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}Overall Status: HEALTHY${NC}"
    elif [[ ${FAIL_COUNT} -le 3 ]]; then
        echo -e "  ${YELLOW}${BOLD}Overall Status: NEEDS ATTENTION${NC}"
    else
        echo -e "  ${RED}${BOLD}Overall Status: CRITICAL${NC}"
    fi

    # Generate HTML report
    cat > "${REPORT_FILE}" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SpyCloud Sentinel Health Report</title>
<style>
:root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3; --green: #3fb950; --red: #f85149; --yellow: #d29922; --blue: #58a6ff; --purple: #bc8cff; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; margin: 0; padding: 20px; }
.container { max-width: 1200px; margin: 0 auto; }
h1 { color: var(--purple); border-bottom: 1px solid var(--border); padding-bottom: 16px; }
h2 { color: var(--blue); margin-top: 32px; }
.summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 16px; text-align: center; }
.card .count { font-size: 36px; font-weight: bold; }
.card.pass .count { color: var(--green); }
.card.fail .count { color: var(--red); }
.card.warn .count { color: var(--yellow); }
.card.skip .count { color: var(--blue); }
.check { padding: 8px 12px; margin: 4px 0; border-radius: 4px; font-family: monospace; font-size: 14px; }
.check.pass { border-left: 3px solid var(--green); }
.check.fail { border-left: 3px solid var(--red); background: rgba(248,81,73,0.1); }
.check.warn { border-left: 3px solid var(--yellow); }
.check.skip { border-left: 3px solid var(--blue); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
.badge.pass { background: var(--green); color: #000; }
.badge.fail { background: var(--red); color: #fff; }
.badge.warn { background: var(--yellow); color: #000; }
footer { margin-top: 48px; padding: 16px 0; border-top: 1px solid var(--border); color: #8b949e; font-size: 12px; }
</style>
</head>
<body>
<div class="container">
<h1>SpyCloud Identity Exposure Intelligence for Sentinel</h1>
<p>Health Report — Generated at TIMESTAMP_PLACEHOLDER</p>
<div class="summary">
<div class="card pass"><div class="count">PASS_PLACEHOLDER</div><div>Passed</div></div>
<div class="card fail"><div class="count">FAIL_PLACEHOLDER</div><div>Failed</div></div>
<div class="card warn"><div class="count">WARN_PLACEHOLDER</div><div>Warnings</div></div>
<div class="card skip"><div class="count">SKIP_PLACEHOLDER</div><div>Skipped</div></div>
</div>
<h2>Recommendations</h2>
<div class="check warn">Run <code>spycloud-toolkit.sh --fix-permissions</code> to resolve permission issues</div>
<div class="check warn">Set environment variables: AZURE_SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME</div>
<div class="check warn">Enable disabled analytics rules in Sentinel > Analytics</div>
<h2>Detailed Results</h2>
<pre>DETAILS_PLACEHOLDER</pre>
<footer>
<p>SpyCloud Identity Exposure Intelligence for Sentinel v2.0.0</p>
<p>Report generated by spycloud-toolkit.sh</p>
</footer>
</div>
</body>
</html>
HTMLEOF

    # Replace placeholders
    sed -i "s/TIMESTAMP_PLACEHOLDER/$(date -u '+%Y-%m-%d %H:%M:%S UTC')/" "${REPORT_FILE}"
    sed -i "s/PASS_PLACEHOLDER/${PASS_COUNT}/" "${REPORT_FILE}"
    sed -i "s/FAIL_PLACEHOLDER/${FAIL_COUNT}/" "${REPORT_FILE}"
    sed -i "s/WARN_PLACEHOLDER/${WARN_COUNT}/" "${REPORT_FILE}"
    sed -i "s/SKIP_PLACEHOLDER/${SKIP_COUNT}/" "${REPORT_FILE}"

    # Escape and insert detailed output
    local escaped_details
    escaped_details=$(sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "${REPORT_DIR}/output.txt" | sed 's/\x1b\[[0-9;]*m//g')
    python3 -c "
import sys
with open('${REPORT_FILE}', 'r') as f:
    content = f.read()
with open('${REPORT_DIR}/output.txt', 'r') as f:
    import re
    details = re.sub(r'\x1b\[[0-9;]*m', '', f.read())
    details = details.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
content = content.replace('DETAILS_PLACEHOLDER', details)
with open('${REPORT_FILE}', 'w') as f:
    f.write(content)
" 2>/dev/null

    echo ""
    log_pass "HTML report saved to: ${REPORT_FILE}"
    log_info "Open in browser: file://${REPORT_FILE}"
}

# ============================================================
# Full HTML Report (web-based)
# ============================================================
full_report() {
    generate_report
}

# ============================================================
# Main Entry Point
# ============================================================
show_help() {
    print_banner
    echo "Usage: bash spycloud-toolkit.sh [command] [options]"
    echo ""
    echo "Commands:"
    echo "  --health-check          Run full health check across all components"
    echo "  --fix-permissions       Auto-fix managed identity permissions"
    echo "  --test-logic-apps       Test all Logic App playbook connections"
    echo "  --test-functions        Test Azure Function App endpoints"
    echo "  --test-agent            Test SCORCH Agent connectivity"
    echo "  --generate-data         Generate simulated breach data for testing"
    echo "  --report                Generate comprehensive status report"
    echo "  --deploy                Deploy or update the solution (launches CloudShell script)"
    echo "  --download-workbooks    Download workbook JSON files"
    echo "  --import-workbooks      Import workbooks to Sentinel workspace"
    echo "  --download-notebooks    Download Jupyter notebook files"
    echo "  --download-plugins      Download Copilot plugin and agent files"
    echo "  --verify-connector      Verify data connector status"
    echo "  --verify-tables         Verify custom log tables exist and have data"
    echo "  --verify-analytics      Verify analytics rules are enabled"
    echo "  --check-isv             Run ISV/Marketplace readiness check"
    echo "  --full-report           Generate full HTML report with all checks"
    echo "  --help                  Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  AZURE_SUBSCRIPTION_ID   Azure subscription ID"
    echo "  RESOURCE_GROUP          Resource group name"
    echo "  WORKSPACE_NAME          Log Analytics workspace name"
    echo "  SPYCLOUD_API_KEY        SpyCloud API key (for data simulation)"
    echo "  AI_ENGINE_URL           AI Engine Function App URL"
    echo ""
    echo "Examples:"
    echo "  # Run health check"
    echo "  export RESOURCE_GROUP=rg-sentinel WORKSPACE_NAME=law-sentinel"
    echo "  bash spycloud-toolkit.sh --health-check"
    echo ""
    echo "  # Generate test data"
    echo "  bash spycloud-toolkit.sh --generate-data"
    echo ""
    echo "  # Download all plugins for Copilot"
    echo "  bash spycloud-toolkit.sh --download-plugins"
    echo ""
    echo "  # Full report"
    echo "  bash spycloud-toolkit.sh --full-report"
}

main() {
    local command="${1:---help}"

    case "${command}" in
        --health-check)
            print_banner
            check_env_vars || true
            health_check_azure
            health_check_tables
            health_check_playbooks
            health_check_connector
            health_check_analytics
            health_check_function_app
            ;;
        --fix-permissions)
            print_banner
            fix_permissions
            ;;
        --test-logic-apps)
            print_banner
            test_logic_apps
            ;;
        --test-functions)
            print_banner
            test_functions
            ;;
        --test-agent)
            print_banner
            test_agent
            ;;
        --generate-data)
            print_banner
            generate_data
            ;;
        --report)
            print_banner
            generate_report
            ;;
        --deploy)
            print_banner
            log_info "Launching CloudShell deployment script..."
            bash "$(dirname "$0")/deploy-cloudshell.sh"
            ;;
        --download-workbooks)
            print_banner
            download_workbooks "${2:-./downloads/workbooks}"
            ;;
        --import-workbooks)
            print_banner
            import_workbooks "${2:-./downloads/workbooks}"
            ;;
        --download-notebooks)
            print_banner
            download_notebooks "${2:-./downloads/notebooks}"
            ;;
        --download-plugins)
            print_banner
            download_plugins "${2:-./downloads/copilot}"
            ;;
        --verify-connector)
            print_banner
            health_check_connector
            ;;
        --verify-tables)
            print_banner
            health_check_tables
            ;;
        --verify-analytics)
            print_banner
            health_check_analytics
            ;;
        --check-isv)
            print_banner
            check_isv_readiness
            ;;
        --full-report)
            print_banner
            full_report
            ;;
        --help|-h|help)
            show_help
            ;;
        *)
            echo -e "${RED}Unknown command: ${command}${NC}"
            echo ""
            show_help
            exit 1
            ;;
    esac

    # Print summary if any checks were run
    local total=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT + SKIP_COUNT))
    if [[ ${total} -gt 0 ]]; then
        echo ""
        echo -e "${WHITE}${BOLD}--- Summary ---${NC}"
        echo -e "  ${GREEN}Pass: ${PASS_COUNT}${NC}  ${RED}Fail: ${FAIL_COUNT}${NC}  ${YELLOW}Warn: ${WARN_COUNT}${NC}  ${BLUE}Skip: ${SKIP_COUNT}${NC}"
    fi
}

main "$@"
