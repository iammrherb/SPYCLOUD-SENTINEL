#!/usr/bin/env bash
#═══════════════════════════════════════════════════════════════════════════════
#  SpyCloud Sentinel — Deploy Wizard
#  Version: 5.0.0
#
#  An interactive, polished deployment wizard for SpyCloud Sentinel.
#  Guides users through configuration, deploys all components, validates
#  the result, and generates a repeatable config file.
#
#  Usage:
#    Interactive:       ./scripts/deploy-wizard.sh
#    Non-interactive:   ./scripts/deploy-wizard.sh --non-interactive --config .spycloud-config.json
#    Resume failed:     ./scripts/deploy-wizard.sh --resume
#    Help:              ./scripts/deploy-wizard.sh --help
#
#  Requires: az (Azure CLI), jq, curl
#  Works in: Azure Cloud Shell, Linux, macOS, WSL, GitHub Actions
#═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

readonly WIZARD_VERSION="5.0.0"
readonly WIZARD_BUILD="20260310"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly CONFIG_FILE="${PROJECT_DIR}/.spycloud-config.json"
readonly STATE_FILE="/tmp/.spycloud-deploy-state.json"
readonly LOGFILE="/tmp/spycloud-wizard-$(date +%Y%m%d-%H%M%S).log"
readonly T0=$(date +%s)

# ─── Terminal Capabilities ────────────────────────────────────────────────────
if [[ -t 1 ]] && command -v tput &>/dev/null && tput colors &>/dev/null; then
    readonly TERM_COLORS=$(tput colors 2>/dev/null || echo 0)
    readonly TERM_COLS=$(tput cols 2>/dev/null || echo 80)
else
    readonly TERM_COLORS=0
    readonly TERM_COLS=80
fi

# ─── Colors & Styles ─────────────────────────────────────────────────────────
if [[ $TERM_COLORS -ge 256 ]]; then
    readonly RED='\033[38;2;255;85;85m'
    readonly GREEN='\033[38;2;80;250;123m'
    readonly YELLOW='\033[38;2;241;250;140m'
    readonly BLUE='\033[38;2;139;233;253m'
    readonly CYAN='\033[38;2;0;180;216m'
    readonly MAGENTA='\033[38;2;255;121;198m'
    readonly TEAL='\033[38;2;0;210;211m'
    readonly CORAL='\033[38;2;224;122;95m'
    readonly PURPLE='\033[38;2;189;147;249m'
    readonly ORANGE='\033[38;2;255;183;77m'
    readonly WHITE='\033[38;2;248;248;242m'
    readonly GRAY='\033[38;2;108;108;108m'
    readonly BOLD='\033[1m'
    readonly DIM='\033[2m'
    readonly ITALIC='\033[3m'
    readonly UNDERLINE='\033[4m'
    readonly BLINK='\033[5m'
    readonly REVERSE='\033[7m'
    readonly NC='\033[0m'
    readonly BG_DARK='\033[48;2;20;20;30m'
    readonly BG_HIGHLIGHT='\033[48;2;40;42;54m'
    readonly CHECK="${GREEN}[ok]${NC}"
    readonly CROSS="${RED}[!!]${NC}"
    readonly WARN_ICON="${YELLOW}[??]${NC}"
    readonly ARROW="${CYAN}-->${NC}"
    readonly DOT="${GRAY}...${NC}"
    readonly BULLET="${TEAL}*${NC}"
elif [[ $TERM_COLORS -ge 8 ]]; then
    readonly RED='\033[0;31m'; readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'; readonly BLUE='\033[0;34m'
    readonly CYAN='\033[0;36m'; readonly MAGENTA='\033[0;35m'
    readonly TEAL='\033[0;36m'; readonly CORAL='\033[0;33m'
    readonly PURPLE='\033[0;35m'; readonly ORANGE='\033[0;33m'
    readonly WHITE='\033[1;37m'; readonly GRAY='\033[0;37m'
    readonly BOLD='\033[1m'; readonly DIM='\033[2m'
    readonly ITALIC=''; readonly UNDERLINE='\033[4m'
    readonly BLINK=''; readonly REVERSE='\033[7m'; readonly NC='\033[0m'
    readonly BG_DARK=''; readonly BG_HIGHLIGHT=''
    readonly CHECK="${GREEN}[ok]${NC}"; readonly CROSS="${RED}[!!]${NC}"
    readonly WARN_ICON="${YELLOW}[??]${NC}"; readonly ARROW="${CYAN}-->${NC}"
    readonly DOT="${GRAY}...${NC}"; readonly BULLET="${TEAL}*${NC}"
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA=''
    readonly TEAL='' CORAL='' PURPLE='' ORANGE='' WHITE='' GRAY=''
    readonly BOLD='' DIM='' ITALIC='' UNDERLINE='' BLINK='' REVERSE='' NC=''
    readonly BG_DARK='' BG_HIGHLIGHT=''
    readonly CHECK='[ok]' CROSS='[!!]' WARN_ICON='[??]'
    readonly ARROW='-->' DOT='...' BULLET='*'
fi

# ─── Configuration Defaults ──────────────────────────────────────────────────
INTERACTIVE=true
CONFIG_PATH=""
RESUME=false
SUBSCRIPTION=""
RESOURCE_GROUP=""
WORKSPACE=""
LOCATION=""
SPYCLOUD_API_KEY=""
ENVIRONMENT="dev"
DEPLOY_ANALYTICS=true
DEPLOY_PLAYBOOKS=true
DEPLOY_WORKBOOKS=true
DEPLOY_NOTEBOOKS=false
DEPLOY_COPILOT=false
TEMPLATE_URL=""

# Azure well-known IDs
readonly MDE_APP_ID="fc780465-2017-40d4-a0c5-307022471b92"
readonly GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"
readonly MON_METRICS_PUB_ROLE="3913510d-42f4-4e42-8a64-420c390055eb"

# Deployment tracking
DEPLOY_STEP=0
DEPLOY_TOTAL=0
DEPLOY_ERRORS=0
DEPLOY_WARNINGS=0
DEPLOY_SUCCESSES=0

# ═════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════

elapsed() {
    local secs=$(( $(date +%s) - T0 ))
    printf "%dm%02ds" $((secs / 60)) $((secs % 60))
}

log_raw() {
    echo "[$(date -Iseconds)] $*" >> "$LOGFILE"
}

# Centered text within a given width
center_text() {
    local text="$1" width="${2:-$TERM_COLS}"
    local stripped
    stripped=$(echo -e "$text" | sed 's/\x1b\[[0-9;]*m//g')
    local len=${#stripped}
    local pad=$(( (width - len) / 2 ))
    [[ $pad -lt 0 ]] && pad=0
    printf "%*s%s" "$pad" "" "$text"
}

# Print a horizontal line
hr() {
    local char="${1:-─}" color="${2:-$GRAY}" width="${3:-$TERM_COLS}"
    local line=""
    for ((i=0; i<width; i++)); do line+="$char"; done
    echo -e "${color}${line}${NC}"
}

# Print a boxed header
box_header() {
    local text="$1" color="${2:-$TEAL}"
    local inner_width=60
    local top_border="" bottom_border="" mid_pad=""
    top_border=$(printf '═%.0s' $(seq 1 $inner_width))
    bottom_border="$top_border"
    local stripped
    stripped=$(echo -e "$text" | sed 's/\x1b\[[0-9;]*m//g')
    local text_len=${#stripped}
    local right_pad=$((inner_width - text_len - 2))
    [[ $right_pad -lt 0 ]] && right_pad=0
    echo ""
    echo -e "  ${color}+${top_border}+${NC}"
    echo -e "  ${color}|${NC} ${BOLD}${text}$(printf '%*s' $right_pad '')${NC} ${color}|${NC}"
    echo -e "  ${color}+${bottom_border}+${NC}"
    echo ""
}

# Spinner animation
spinner() {
    local pid=$1 msg="${2:-Working...}"
    local frames=('   [    ]' '   [=   ]' '   [==  ]' '   [=== ]' '   [ ===]' '   [  ==]' '   [   =]' '   [    ]' '   [   =]' '   [  ==]' '   [ ===]' '   [=== ]' '   [==  ]' '   [=   ]')
    local i=0
    tput civis 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}${frames[$i]}${NC} ${msg}"
        i=$(( (i + 1) % ${#frames[@]} ))
        sleep 0.12
    done
    tput cnorm 2>/dev/null || true
    printf "\r%*s\r" $((${#msg} + 20)) ""
}

# Progress bar
progress_bar() {
    local current=$1 total=$2 label="${3:-}" width=40
    local pct=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done  # Use block character directly
    for ((i=0; i<empty; i++)); do bar+="░"; done    # Use light shade directly
    printf "\r   ${TEAL}${bar}${NC} ${BOLD}%3d%%${NC} ${DIM}%s${NC}" "$pct" "$label"
    [[ $current -eq $total ]] && echo ""
}

# Typed text effect for that extra polish
type_text() {
    local text="$1" delay="${2:-0.02}"
    if ! $INTERACTIVE; then
        echo -e "$text"
        return
    fi
    local i
    for ((i=0; i<${#text}; i++)); do
        printf "%s" "${text:$i:1}"
        sleep "$delay"
    done
    echo ""
}

# ─── Logging ──────────────────────────────────────────────────────────────────
info()  { echo -e "  ${BLUE}[info]${NC}  $1"; log_raw "INFO: $1"; }
ok()    { echo -e "  ${CHECK}  $1"; log_raw " OK : $1"; ((DEPLOY_SUCCESSES++)) || true; }
warn()  { echo -e "  ${WARN_ICON}  $1"; log_raw "WARN: $1"; ((DEPLOY_WARNINGS++)) || true; }
fail()  { echo -e "  ${CROSS}  $1"; log_raw "FAIL: $1"; ((DEPLOY_ERRORS++)) || true; }

# ─── Input Functions ──────────────────────────────────────────────────────────

# Prompt for text input with default
prompt_input() {
    local prompt="$1" default="${2:-}" var_name="$3" secret="${4:-false}"
    local value
    if $secret; then
        echo -ne "   ${ARROW} ${prompt}"
        [[ -n "$default" ]] && echo -ne " ${DIM}[****]${NC}" || echo -ne " ${DIM}(required)${NC}"
        echo -ne ": "
        read -rs value
        echo ""
    else
        echo -ne "   ${ARROW} ${prompt}"
        [[ -n "$default" ]] && echo -ne " ${DIM}[${default}]${NC}"
        echo -ne ": "
        read -r value
    fi
    value="${value:-$default}"
    eval "$var_name='$value'"
}

# Prompt for numbered selection from a list
prompt_select() {
    local prompt="$1" var_name="$2"
    shift 2
    local options=("$@")
    local i

    echo -e "   ${ARROW} ${prompt}:"
    echo ""
    for i in "${!options[@]}"; do
        local item="${options[$i]}"
        local marker="  "
        # Check for recommended items (marked with *)
        if [[ "$item" == *"*"* ]]; then
            item="${item%\*}"
            marker="${GREEN}<-${NC}"
        fi
        printf "       ${TEAL}[%d]${NC}  %-30s %s\n" "$((i+1))" "$item" "$marker"
    done
    echo ""
    echo -ne "       ${DIM}Enter number${NC}: "
    local choice
    read -r choice
    choice="${choice:-1}"

    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
        local selected="${options[$((choice-1))]}"
        selected="${selected%\*}"
        eval "$var_name='$selected'"
    else
        warn "Invalid selection, using first option"
        local selected="${options[0]}"
        selected="${selected%\*}"
        eval "$var_name='$selected'"
    fi
    echo ""
}

# Prompt for yes/no
prompt_yn() {
    local prompt="$1" default="${2:-y}"
    local hint
    [[ "$default" == "y" ]] && hint="Y/n" || hint="y/N"
    echo -ne "   ${ARROW} ${prompt} ${DIM}[${hint}]${NC}: "
    local ans
    read -r ans
    ans="${ans:-$default}"
    [[ "$ans" =~ ^[Yy] ]]
}

# Toggle component selection
prompt_components() {
    echo -e "   ${ARROW} Select components to deploy:"
    echo ""
    echo -e "       ${DIM}Toggle each component (Enter = accept shown default):${NC}"
    echo ""

    local items=("Analytics Rules" "Playbooks (Logic Apps)" "Workbooks (Dashboards)" "Notebooks (Jupyter)" "Security Copilot Plugin")
    local defaults=("y" "y" "y" "n" "n")
    local vars=("DEPLOY_ANALYTICS" "DEPLOY_PLAYBOOKS" "DEPLOY_WORKBOOKS" "DEPLOY_NOTEBOOKS" "DEPLOY_COPILOT")

    for i in "${!items[@]}"; do
        local def="${defaults[$i]}"
        local hint
        [[ "$def" == "y" ]] && hint="${GREEN}ON${NC}" || hint="${DIM}OFF${NC}"
        echo -ne "       ${TEAL}[$((i+1))]${NC}  %-30s [${hint}]  ${DIM}(y/n)${NC}: " "${items[$i]}"
        local ans
        read -r ans
        ans="${ans:-$def}"
        if [[ "$ans" =~ ^[Yy] ]]; then
            eval "${vars[$i]}=true"
            echo -e "\033[1A\033[2K       ${TEAL}[$((i+1))]${NC}  $(printf '%-30s' "${items[$i]}") [${GREEN}ON${NC}]"
        else
            eval "${vars[$i]}=false"
            echo -e "\033[1A\033[2K       ${TEAL}[$((i+1))]${NC}  $(printf '%-30s' "${items[$i]}") [${DIM}OFF${NC}]"
        fi
    done
    echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# WELCOME BANNER
# ═════════════════════════════════════════════════════════════════════════════

show_banner() {
    clear 2>/dev/null || true
    echo ""
    echo ""
    if [[ $TERM_COLORS -ge 256 ]]; then
        # Gradient-colored ASCII art
        echo -e "  \033[38;2;0;150;200m  ____              ____ _                 _   \033[38;2;0;170;210m ____            _   _            _ ${NC}"
        echo -e "  \033[38;2;0;155;205m / ___| _ __  _   _/ ___| | ___  _   _  __| |  \033[38;2;0;175;215m/ ___|  ___ _ __| |_(_)_ __   ___| |${NC}"
        echo -e "  \033[38;2;0;160;210m \\___ \\| '_ \\| | | \\___ \\ |/ _ \\| | | |/ _\` |  \033[38;2;0;180;220m\\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ |${NC}"
        echo -e "  \033[38;2;0;170;215m  ___) | |_) | |_| |___) | | (_) | |_| | (_| |  \033[38;2;0;190;225m ___) |  __/ | | | |_| | | | |  __/ |${NC}"
        echo -e "  \033[38;2;0;180;220m |____/| .__/ \\__, |____/|_|\\___/ \\__,_|\\__,_|  \033[38;2;0;200;230m|____/ \\___|_| |_|\\__|_|_| |_|\\___|_|${NC}"
        echo -e "  \033[38;2;0;190;225m       |_|    |___/                              ${NC}"
    else
        echo -e "  ${BOLD}  ____              ____ _                 _    ____            _   _            _${NC}"
        echo -e "  ${BOLD} / ___| _ __  _   _/ ___| | ___  _   _  __| |  / ___|  ___ _ __| |_(_)_ __   ___| |${NC}"
        echo -e "  ${BOLD} \\___ \\| '_ \\| | | \\___ \\ |/ _ \\| | | |/ _\` |  \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ |${NC}"
        echo -e "  ${BOLD}  ___) | |_) | |_| |___) | | (_) | |_| | (_| |   ___) |  __/ | | | |_| | | | |  __/ |${NC}"
        echo -e "  ${BOLD} |____/| .__/ \\__, |____/|_|\\___/ \\__,_|\\__,_|  |____/ \\___|_| |_|\\__|_|_| |_|\\___|_|${NC}"
        echo -e "  ${BOLD}       |_|    |___/${NC}"
    fi
    echo ""
    echo -e "  ${TEAL}$(printf '%.0s-' $(seq 1 72))${NC}"
    echo -e "  ${BOLD}${WHITE}  Deploy Wizard${NC}  ${DIM}v${WIZARD_VERSION}${NC}  ${DIM}|${NC}  ${DIM}Microsoft Sentinel Threat Intelligence${NC}"
    echo -e "  ${TEAL}$(printf '%.0s-' $(seq 1 72))${NC}"
    echo ""
    echo -e "  ${DIM}  Unified deployment for analytics, playbooks, workbooks & more${NC}"
    echo -e "  ${DIM}  Log: ${LOGFILE}${NC}"
    echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1: PREREQUISITES CHECK
# ═════════════════════════════════════════════════════════════════════════════

check_prerequisites() {
    box_header "Phase 1/7 -- Prerequisites Check" "$CYAN"

    local all_ok=true

    # Check required tools
    local tools=("az:Azure CLI:https://aka.ms/installazurecli" "jq:JSON processor:https://stedolan.github.io/jq/download/" "curl:HTTP client:included in most systems")

    for tool_info in "${tools[@]}"; do
        IFS=':' read -r cmd name url <<< "$tool_info"
        if command -v "$cmd" &>/dev/null; then
            local ver
            case "$cmd" in
                az)   ver=$(az version --query '"azure-cli"' -o tsv 2>/dev/null || echo "unknown");;
                jq)   ver=$(jq --version 2>/dev/null || echo "unknown");;
                curl) ver=$(curl --version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown");;
            esac
            ok "${name} ${DIM}(${ver})${NC}"
        else
            fail "${name} not found -- install from ${UNDERLINE}${url}${NC}"
            all_ok=false
        fi
    done

    # Check optional tools
    for cmd in python3 git; do
        if command -v "$cmd" &>/dev/null; then
            ok "${cmd} available ${DIM}(optional)${NC}"
        else
            info "${cmd} not found ${DIM}(optional, some features may be limited)${NC}"
        fi
    done

    echo ""

    # Check Azure login status
    echo -e "  ${BOLD}Azure Authentication${NC}"
    echo ""
    if az account show &>/dev/null 2>&1; then
        local acct_name acct_id tenant_id
        acct_name=$(az account show --query name -o tsv 2>/dev/null)
        acct_id=$(az account show --query id -o tsv 2>/dev/null)
        tenant_id=$(az account show --query tenantId -o tsv 2>/dev/null)
        ok "Logged in to Azure"
        info "Account:      ${BOLD}${acct_name}${NC}"
        info "Subscription: ${DIM}${acct_id}${NC}"
        info "Tenant:       ${DIM}${tenant_id}${NC}"
    else
        warn "Not logged in to Azure"
        if $INTERACTIVE; then
            echo ""
            info "Opening browser for Azure login..."
            if az login --use-device-code 2>/dev/null || az login 2>/dev/null; then
                ok "Successfully authenticated"
            else
                fail "Azure login failed -- please run 'az login' manually"
                all_ok=false
            fi
        else
            fail "Azure authentication required. Run 'az login' first."
            all_ok=false
        fi
    fi

    echo ""

    # Check directory context
    echo -e "  ${BOLD}Project Context${NC}"
    echo ""
    if [[ -f "${PROJECT_DIR}/azuredeploy.json" ]]; then
        ok "ARM template found ${DIM}(azuredeploy.json)${NC}"
    else
        info "No local ARM template -- will use remote from GitHub"
    fi

    if [[ -f "$CONFIG_FILE" ]]; then
        ok "Existing config found ${DIM}(${CONFIG_FILE})${NC}"
    else
        info "No previous config -- will create new"
    fi

    if [[ -f "$STATE_FILE" ]]; then
        local prev_step
        prev_step=$(jq -r '.last_completed_step // "unknown"' "$STATE_FILE" 2>/dev/null || echo "unknown")
        warn "Previous deployment state found (step: ${prev_step})"
        if $INTERACTIVE; then
            if prompt_yn "Resume from previous state?"; then
                RESUME=true
            fi
        fi
    fi

    echo ""

    if ! $all_ok; then
        echo -e "  ${RED}${BOLD}Prerequisites not met. Please install missing tools and retry.${NC}"
        echo ""
        exit 1
    fi

    ok "All prerequisites satisfied"
    echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2: INTERACTIVE CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

configure_deployment() {
    box_header "Phase 2/7 -- Deployment Configuration" "$CYAN"

    # Load existing config if present and user wants to
    if [[ -f "$CONFIG_FILE" ]] && $INTERACTIVE; then
        echo -e "  ${DIM}Found existing configuration at ${CONFIG_FILE}${NC}"
        echo ""
        if prompt_yn "Load previous configuration?" "y"; then
            load_config "$CONFIG_FILE"
            echo ""
            info "Configuration loaded. You can override any value below."
            echo ""
        fi
    fi

    if ! $INTERACTIVE; then
        # Non-interactive: everything must come from config or CLI
        info "Non-interactive mode -- using config/CLI values"
        validate_config
        return
    fi

    # ── Subscription Selection ──
    echo -e "  ${BOLD}${WHITE}1. Azure Subscription${NC}"
    echo ""

    local subs sub_names sub_ids current_sub
    current_sub=$(az account show --query id -o tsv 2>/dev/null)

    # Fetch subscriptions
    mapfile -t sub_names < <(az account list --query '[].name' -o tsv 2>/dev/null)
    mapfile -t sub_ids < <(az account list --query '[].id' -o tsv 2>/dev/null)

    if [[ ${#sub_names[@]} -eq 0 ]]; then
        fail "No Azure subscriptions found"
        exit 1
    elif [[ ${#sub_names[@]} -eq 1 ]]; then
        SUBSCRIPTION="${sub_ids[0]}"
        ok "Using subscription: ${BOLD}${sub_names[0]}${NC}"
    else
        echo -e "   ${ARROW} Available subscriptions:"
        echo ""
        for i in "${!sub_names[@]}"; do
            local marker=""
            [[ "${sub_ids[$i]}" == "$current_sub" ]] && marker=" ${GREEN}<- current${NC}"
            printf "       ${TEAL}[%d]${NC}  %-45s ${DIM}%s${NC}%b\n" "$((i+1))" "${sub_names[$i]}" "${sub_ids[$i]:0:13}..." "$marker"
        done
        echo ""
        echo -ne "       ${DIM}Select subscription${NC} ${DIM}[1]${NC}: "
        local sub_choice
        read -r sub_choice
        sub_choice="${sub_choice:-1}"
        if [[ "$sub_choice" =~ ^[0-9]+$ ]] && (( sub_choice >= 1 && sub_choice <= ${#sub_ids[@]} )); then
            SUBSCRIPTION="${sub_ids[$((sub_choice-1))]}"
        else
            SUBSCRIPTION="${sub_ids[0]}"
        fi
        az account set --subscription "$SUBSCRIPTION" 2>/dev/null
        ok "Selected: ${BOLD}$(az account show --query name -o tsv 2>/dev/null)${NC}"
    fi
    echo ""

    # ── Resource Group ──
    echo -e "  ${BOLD}${WHITE}2. Resource Group${NC}"
    echo ""

    if $INTERACTIVE; then
        local rg_choice
        echo -e "   ${ARROW} Resource group options:"
        echo ""
        echo -e "       ${TEAL}[1]${NC}  Create new resource group"
        echo -e "       ${TEAL}[2]${NC}  Select existing resource group"
        echo ""
        echo -ne "       ${DIM}Choose${NC} ${DIM}[1]${NC}: "
        read -r rg_choice
        rg_choice="${rg_choice:-1}"

        if [[ "$rg_choice" == "2" ]]; then
            mapfile -t rg_names < <(az group list --query '[].name' -o tsv 2>/dev/null | sort)
            if [[ ${#rg_names[@]} -eq 0 ]]; then
                info "No existing resource groups found. Creating new."
                rg_choice="1"
            else
                echo ""
                echo -e "   ${ARROW} Existing resource groups:"
                echo ""
                for i in "${!rg_names[@]}"; do
                    local rg_loc
                    rg_loc=$(az group show --name "${rg_names[$i]}" --query location -o tsv 2>/dev/null)
                    printf "       ${TEAL}[%d]${NC}  %-35s ${DIM}(%s)${NC}\n" "$((i+1))" "${rg_names[$i]}" "$rg_loc"
                done
                echo ""
                echo -ne "       ${DIM}Select${NC}: "
                local rg_sel
                read -r rg_sel
                if [[ "$rg_sel" =~ ^[0-9]+$ ]] && (( rg_sel >= 1 && rg_sel <= ${#rg_names[@]} )); then
                    RESOURCE_GROUP="${rg_names[$((rg_sel-1))]}"
                fi
            fi
        fi

        if [[ "$rg_choice" == "1" ]] || [[ -z "$RESOURCE_GROUP" ]]; then
            prompt_input "Resource group name" "spycloud-sentinel-rg" RESOURCE_GROUP
        fi
    fi
    ok "Resource group: ${BOLD}${RESOURCE_GROUP}${NC}"
    echo ""

    # ── Region Selection ──
    echo -e "  ${BOLD}${WHITE}3. Azure Region${NC}"
    echo ""

    local regions=("eastus*" "eastus2*" "westus2" "centralus" "northeurope" "westeurope*" "uksouth" "australiaeast" "southeastasia" "japaneast")
    local region_labels=("East US (recommended)" "East US 2 (recommended)" "West US 2" "Central US" "North Europe" "West Europe (recommended)" "UK South" "Australia East" "Southeast Asia" "Japan East")

    echo -e "   ${ARROW} Select deployment region:"
    echo -e "      ${DIM}Recommended regions have full Sentinel feature support${NC}"
    echo ""

    for i in "${!regions[@]}"; do
        local reg="${regions[$i]}"
        local label="${region_labels[$i]}"
        local clean_reg="${reg%\*}"
        local marker=""
        [[ "$reg" == *"*" ]] && marker="  ${GREEN}<-${NC}"
        printf "       ${TEAL}[%2d]${NC}  %-18s ${DIM}%s${NC}%b\n" "$((i+1))" "$clean_reg" "$label" "$marker"
    done
    echo ""
    echo -ne "       ${DIM}Select region${NC} ${DIM}[1]${NC}: "
    local reg_choice
    read -r reg_choice
    reg_choice="${reg_choice:-1}"

    if [[ "$reg_choice" =~ ^[0-9]+$ ]] && (( reg_choice >= 1 && reg_choice <= ${#regions[@]} )); then
        LOCATION="${regions[$((reg_choice-1))]}"
        LOCATION="${LOCATION%\*}"
    else
        LOCATION="eastus"
    fi
    ok "Region: ${BOLD}${LOCATION}${NC}"
    echo ""

    # ── SpyCloud API Key ──
    echo -e "  ${BOLD}${WHITE}4. SpyCloud API Key${NC}"
    echo -e "     ${DIM}Get yours at: https://portal.spycloud.com -> Settings -> API Keys${NC}"
    echo ""

    if [[ -z "$SPYCLOUD_API_KEY" ]]; then
        prompt_input "SpyCloud API key" "" SPYCLOUD_API_KEY true
    fi

    if [[ -z "$SPYCLOUD_API_KEY" ]]; then
        fail "SpyCloud API key is required"
        exit 1
    fi

    # Validate API key
    echo -ne "   ${DOT} Validating API key"
    local api_status
    api_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer ${SPYCLOUD_API_KEY}" \
        "https://api.spycloud.io/v2/breach/catalog?limit=1" 2>/dev/null || echo "000")
    log_raw "API validation response: ${api_status}"

    if [[ "$api_status" == "200" ]]; then
        echo -e "\r   ${CHECK}  API key validated successfully"
    elif [[ "$api_status" == "401" || "$api_status" == "403" ]]; then
        echo -e "\r   ${CROSS}  API key rejected (HTTP ${api_status})"
        warn "The key may be invalid or expired. Continuing anyway..."
    else
        echo -e "\r   ${WARN_ICON}  Could not reach SpyCloud API (HTTP ${api_status})"
        info "This may be a network issue. Continuing with provided key..."
    fi
    echo ""

    # ── Workspace Name ──
    echo -e "  ${BOLD}${WHITE}5. Log Analytics Workspace${NC}"
    echo -e "     ${DIM}Sentinel will be enabled on this workspace${NC}"
    echo ""
    prompt_input "Workspace name" "spycloud-sentinel-ws" WORKSPACE
    ok "Workspace: ${BOLD}${WORKSPACE}${NC}"
    echo ""

    # ── Component Selection ──
    echo -e "  ${BOLD}${WHITE}6. Deployment Components${NC}"
    echo ""
    prompt_components
    echo ""

    # ── Environment Tag ──
    echo -e "  ${BOLD}${WHITE}7. Environment${NC}"
    echo ""
    local envs=("dev" "staging" "prod")
    prompt_select "Select environment" ENVIRONMENT "${envs[@]}"
    ok "Environment: ${BOLD}${ENVIRONMENT}${NC}"
    echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3: CONFIG FILE GENERATION
# ═════════════════════════════════════════════════════════════════════════════

generate_config() {
    box_header "Phase 3/7 -- Configuration File" "$CYAN"

    local config_json
    config_json=$(cat <<CFGEOF
{
  "_metadata": {
    "generated_by": "SpyCloud Sentinel Deploy Wizard v${WIZARD_VERSION}",
    "generated_at": "$(date -Iseconds)",
    "schema_version": "1.0"
  },
  "subscription": "${SUBSCRIPTION}",
  "resource_group": "${RESOURCE_GROUP}",
  "workspace": "${WORKSPACE}",
  "location": "${LOCATION}",
  "environment": "${ENVIRONMENT}",
  "components": {
    "analytics": ${DEPLOY_ANALYTICS},
    "playbooks": ${DEPLOY_PLAYBOOKS},
    "workbooks": ${DEPLOY_WORKBOOKS},
    "notebooks": ${DEPLOY_NOTEBOOKS},
    "copilot": ${DEPLOY_COPILOT}
  },
  "api_key_set": true,
  "template_url": "${TEMPLATE_URL}"
}
CFGEOF
)

    echo "$config_json" > "$CONFIG_FILE"
    ok "Config saved to ${BOLD}${CONFIG_FILE}${NC}"
    echo ""
    echo -e "  ${DIM}You can reuse this config for future deployments:${NC}"
    echo -e "  ${DIM}  ./scripts/deploy-wizard.sh --non-interactive --config ${CONFIG_FILE}${NC}"
    echo ""
    info "Note: API key is NOT stored in the config file for security."
    info "Pass it via --api-key or SPYCLOUD_API_KEY env variable."
    echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 4: DEPLOYMENT PLAN & CONFIRMATION
# ═════════════════════════════════════════════════════════════════════════════

show_deployment_plan() {
    box_header "Phase 4/7 -- Deployment Plan" "$CYAN"

    local component_count=0
    $DEPLOY_ANALYTICS && ((component_count++)) || true
    $DEPLOY_PLAYBOOKS && ((component_count++)) || true
    $DEPLOY_WORKBOOKS && ((component_count++)) || true
    $DEPLOY_NOTEBOOKS && ((component_count++)) || true
    $DEPLOY_COPILOT && ((component_count++)) || true

    echo -e "  ${TEAL}+$(printf '═%.0s' $(seq 1 60))+${NC}"
    echo -e "  ${TEAL}|${NC}  ${BOLD}${WHITE}DEPLOYMENT PLAN${NC}$(printf '%*s' 44 '')${TEAL}|${NC}"
    echo -e "  ${TEAL}+$(printf '─%.0s' $(seq 1 60))+${NC}"
    echo -e "  ${TEAL}|${NC}                                                            ${TEAL}|${NC}"
    printf "  ${TEAL}|${NC}  %-18s  ${BOLD}%-38s${NC}${TEAL}|${NC}\n" "Subscription:" "$(az account show --query name -o tsv 2>/dev/null | cut -c1-38)"
    printf "  ${TEAL}|${NC}  %-18s  ${BOLD}%-38s${NC}${TEAL}|${NC}\n" "Resource Group:" "${RESOURCE_GROUP:0:38}"
    printf "  ${TEAL}|${NC}  %-18s  ${BOLD}%-38s${NC}${TEAL}|${NC}\n" "Workspace:" "${WORKSPACE:0:38}"
    printf "  ${TEAL}|${NC}  %-18s  ${BOLD}%-38s${NC}${TEAL}|${NC}\n" "Region:" "${LOCATION:0:38}"
    printf "  ${TEAL}|${NC}  %-18s  ${BOLD}%-38s${NC}${TEAL}|${NC}\n" "Environment:" "${ENVIRONMENT:0:38}"
    printf "  ${TEAL}|${NC}  %-18s  ${BOLD}%-38s${NC}${TEAL}|${NC}\n" "API Key:" "${SPYCLOUD_API_KEY:0:8}********************************"
    echo -e "  ${TEAL}|${NC}                                                            ${TEAL}|${NC}"
    echo -e "  ${TEAL}+$(printf '─%.0s' $(seq 1 60))+${NC}"
    echo -e "  ${TEAL}|${NC}  ${BOLD}Components (${component_count})${NC}$(printf '%*s' $((46 - ${#component_count})) '')${TEAL}|${NC}"
    echo -e "  ${TEAL}+$(printf '─%.0s' $(seq 1 60))+${NC}"

    local comp_line
    comp_line() {
        local name="$1" enabled="$2"
        local status
        $enabled && status="${GREEN}  DEPLOY${NC}" || status="${DIM}    SKIP${NC}"
        printf "  ${TEAL}|${NC}    %-40s  %b       ${TEAL}|${NC}\n" "$name" "$status"
    }

    comp_line "Analytics Rules" "$DEPLOY_ANALYTICS"
    comp_line "Playbooks (Logic Apps)" "$DEPLOY_PLAYBOOKS"
    comp_line "Workbooks (Dashboards)" "$DEPLOY_WORKBOOKS"
    comp_line "Notebooks (Jupyter)" "$DEPLOY_NOTEBOOKS"
    comp_line "Security Copilot Plugin" "$DEPLOY_COPILOT"

    echo -e "  ${TEAL}|${NC}                                                            ${TEAL}|${NC}"
    echo -e "  ${TEAL}+$(printf '═%.0s' $(seq 1 60))+${NC}"
    echo ""

    if $INTERACTIVE; then
        echo -e "  ${YELLOW}${BOLD}This will create or modify Azure resources in your subscription.${NC}"
        echo ""
        if ! prompt_yn "Proceed with deployment?" "y"; then
            echo ""
            info "Deployment cancelled by user."
            info "Your configuration has been saved to ${CONFIG_FILE}"
            echo ""
            exit 0
        fi
    fi

    echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 5: DEPLOYMENT EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

save_state() {
    local step_name="$1" status="${2:-in_progress}"
    cat > "$STATE_FILE" <<STEOF
{
  "last_completed_step": "${step_name}",
  "status": "${status}",
  "timestamp": "$(date -Iseconds)",
  "resource_group": "${RESOURCE_GROUP}",
  "workspace": "${WORKSPACE}",
  "location": "${LOCATION}",
  "subscription": "${SUBSCRIPTION}",
  "deploy_errors": ${DEPLOY_ERRORS},
  "deploy_warnings": ${DEPLOY_WARNINGS}
}
STEOF
    log_raw "State saved: step=${step_name} status=${status}"
}

deploy_step() {
    local step_num="$1" step_name="$2" step_desc="$3"
    ((DEPLOY_STEP++)) || true
    echo ""
    echo -e "  ${TEAL}[$step_num]${NC} ${BOLD}${step_desc}${NC}"
    echo -e "  $(printf '%.0s-' $(seq 1 50))"
    echo ""
    save_state "$step_name" "in_progress"
}

execute_deployment() {
    box_header "Phase 5/7 -- Deploying Resources" "$GREEN"

    DEPLOY_TOTAL=6
    DEPLOY_STEP=0

    echo -e "  ${DIM}Deployment started at $(date '+%H:%M:%S')${NC}"
    echo -e "  ${DIM}Estimated time: 5-12 minutes${NC}"
    echo ""
    progress_bar 0 $DEPLOY_TOTAL "Initializing..."

    # ── Step 1: Resource Group ──
    deploy_step "1/$DEPLOY_TOTAL" "resource_group" "Resource Group"
    progress_bar 1 $DEPLOY_TOTAL "Resource group..."

    if az group show --name "$RESOURCE_GROUP" &>/dev/null 2>&1; then
        ok "Resource group exists: ${BOLD}${RESOURCE_GROUP}${NC}"
    else
        info "Creating resource group: ${RESOURCE_GROUP} in ${LOCATION}..."
        if az group create --name "$RESOURCE_GROUP" --location "$LOCATION" \
            --tags solution=SpyCloud-Sentinel version="${WIZARD_VERSION}" environment="${ENVIRONMENT}" \
            managed-by=deploy-wizard -o none 2>>"$LOGFILE"; then
            ok "Created resource group: ${BOLD}${RESOURCE_GROUP}${NC}"
        else
            fail "Failed to create resource group"
            handle_deployment_error "resource_group"
            return 1
        fi
    fi

    save_state "resource_group" "complete"

    # ── Step 2: ARM Template Deployment ──
    deploy_step "2/$DEPLOY_TOTAL" "arm_template" "ARM Template Deployment"
    progress_bar 2 $DEPLOY_TOTAL "ARM template..."

    # Resolve template
    if [[ -z "$TEMPLATE_URL" ]]; then
        if [[ -f "${PROJECT_DIR}/azuredeploy.json" ]]; then
            TEMPLATE_URL="${PROJECT_DIR}/azuredeploy.json"
        else
            TEMPLATE_URL="https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/azuredeploy.json"
        fi
    fi

    info "Template: ${DIM}${TEMPLATE_URL}${NC}"

    local deploy_name="spycloud-wizard-$(date +%Y%m%d%H%M%S)"
    local template_flag
    if [[ "$TEMPLATE_URL" == http* ]]; then
        template_flag="--template-uri"
    else
        template_flag="--template-file"
    fi

    local deploy_cmd="az deployment group create \
        --name $deploy_name \
        --resource-group $RESOURCE_GROUP \
        $template_flag $TEMPLATE_URL \
        --parameters \
            workspace=$WORKSPACE \
            createNewWorkspace=true \
            spycloudApiKey=$SPYCLOUD_API_KEY \
            deploymentRegion=$LOCATION \
            resourceGroupName=$RESOURCE_GROUP \
            subscription=$SUBSCRIPTION \
            enableMdePlaybook=$DEPLOY_PLAYBOOKS \
            enableCaPlaybook=$DEPLOY_PLAYBOOKS \
            enableKeyVault=true \
            enableAnalyticsRule=$DEPLOY_ANALYTICS \
            enableAutomationRule=$DEPLOY_ANALYTICS \
            enableAnalyticsRulesLibrary=$DEPLOY_ANALYTICS \
        -o none"

    log_raw "Deploy command: $deploy_cmd"

    info "Deploying... ${DIM}(this typically takes 3-8 minutes)${NC}"
    echo ""

    # Run deployment with spinner
    eval "$deploy_cmd" >>"$LOGFILE" 2>&1 &
    local deploy_pid=$!
    spinner $deploy_pid "Deploying ARM template to ${RESOURCE_GROUP}..."
    wait $deploy_pid
    local deploy_exit=$?

    if [[ $deploy_exit -eq 0 ]]; then
        ok "ARM template deployed successfully"
    else
        warn "ARM deployment exited with code ${deploy_exit}"
        local state
        state=$(az deployment group show --name "$deploy_name" -g "$RESOURCE_GROUP" \
            --query "properties.provisioningState" -o tsv 2>/dev/null || echo "Unknown")
        warn "Deployment state: ${state}"
        if [[ "$state" == "Succeeded" ]]; then
            ok "Deployment ultimately succeeded (non-zero exit was transient)"
        else
            fail "ARM deployment failed (state: ${state})"
            info "Check log: ${LOGFILE}"
            handle_deployment_error "arm_template"
        fi
    fi

    save_state "arm_template" "complete"

    # ── Step 3: Wait for Async Resources ──
    deploy_step "3/$DEPLOY_TOTAL" "async_wait" "Waiting for Async Resources"
    progress_bar 3 $DEPLOY_TOTAL "Waiting for resources..."

    info "Content template creates DCR + custom tables asynchronously."
    info "Waiting 60 seconds for resources to finalize..."
    echo ""

    for i in $(seq 1 12); do
        progress_bar $((i)) 12 "$(( i * 5 ))s / 60s"
        sleep 5
    done
    ok "Async wait complete"

    save_state "async_wait" "complete"

    # ── Step 4: Resolve DCE/DCR ──
    deploy_step "4/$DEPLOY_TOTAL" "resolve_endpoints" "Resolve Data Collection Endpoints"
    progress_bar 4 $DEPLOY_TOTAL "Resolving endpoints..."

    local dce_name="dce-spycloud-${WORKSPACE}" dcr_name="dcr-spycloud-${WORKSPACE}"
    local dce_uri="" dcr_id="" dcr_rid=""

    for attempt in 1 2 3 4 5; do
        dce_uri=$(az monitor data-collection endpoint show --name "$dce_name" -g "$RESOURCE_GROUP" \
            --query "logsIngestion.endpoint" -o tsv 2>/dev/null || echo "")
        dcr_id=$(az monitor data-collection rule show --name "$dcr_name" -g "$RESOURCE_GROUP" \
            --query "immutableId" -o tsv 2>/dev/null || echo "")
        dcr_rid=$(az monitor data-collection rule show --name "$dcr_name" -g "$RESOURCE_GROUP" \
            --query "id" -o tsv 2>/dev/null || echo "")

        if [[ -n "$dce_uri" && -n "$dcr_id" ]]; then
            break
        fi
        if [[ $attempt -lt 5 ]]; then
            warn "Attempt ${attempt}/5 -- resources not ready, waiting 30s..."
            sleep 30
        fi
    done

    [[ -n "$dce_uri" ]] && ok "DCE: ${DIM}${dce_uri}${NC}" || warn "DCE not resolved yet"
    [[ -n "$dcr_id" ]]  && ok "DCR: ${DIM}${dcr_id}${NC}" || warn "DCR not resolved yet"

    save_state "resolve_endpoints" "complete"

    # ── Step 5: RBAC Assignments ──
    deploy_step "5/$DEPLOY_TOTAL" "rbac" "RBAC & API Permissions"
    progress_bar 5 $DEPLOY_TOTAL "Setting permissions..."

    if $DEPLOY_PLAYBOOKS; then
        local mde_pb="SpyCloud-MDE-Remediation-${WORKSPACE}"
        local ca_pb="SpyCloud-CA-Remediation-${WORKSPACE}"

        for pb_name in "$mde_pb" "$ca_pb"; do
            local pid
            pid=$(az logic workflow show --name "$pb_name" -g "$RESOURCE_GROUP" \
                --query "identity.principalId" -o tsv 2>/dev/null || echo "")

            if [[ -n "$pid" && -n "$dcr_rid" ]]; then
                if az role assignment create \
                    --assignee-object-id "$pid" \
                    --assignee-principal-type ServicePrincipal \
                    --role "$MON_METRICS_PUB_ROLE" --scope "$dcr_rid" \
                    -o none 2>>"$LOGFILE"; then
                    ok "RBAC assigned: ${DIM}${pb_name}${NC}"
                else
                    warn "RBAC may already exist: ${DIM}${pb_name}${NC}"
                fi
            else
                warn "Skipping ${pb_name} -- not found or DCR unavailable"
            fi
        done
    else
        info "Playbooks not deployed -- skipping RBAC"
    fi

    save_state "rbac" "complete"

    # ── Step 6: Finalize ──
    deploy_step "6/$DEPLOY_TOTAL" "finalize" "Finalizing Deployment"
    progress_bar 6 $DEPLOY_TOTAL "Complete!"

    # Tag resource group with deployment info
    az group update --name "$RESOURCE_GROUP" \
        --tags solution=SpyCloud-Sentinel version="${WIZARD_VERSION}" \
        environment="${ENVIRONMENT}" \
        deployed-at="$(date -Iseconds)" \
        deployed-by=deploy-wizard \
        -o none 2>>"$LOGFILE" || true

    ok "Deployment finalized"
    save_state "finalize" "complete"

    echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 6: POST-DEPLOY VALIDATION
# ═════════════════════════════════════════════════════════════════════════════

run_validation() {
    box_header "Phase 6/7 -- Post-Deploy Validation" "$CYAN"

    local v_pass=0 v_warn=0 v_fail=0

    v_check() {
        local name="$1"; shift
        if "$@" &>/dev/null 2>&1; then
            ok "$name"
            ((v_pass++)) || true
        else
            warn "$name"
            ((v_warn++)) || true
        fi
    }

    echo -e "  ${BOLD}Resource Verification${NC}"
    echo ""

    v_check "Log Analytics Workspace" \
        az monitor log-analytics workspace show --workspace-name "$WORKSPACE" -g "$RESOURCE_GROUP"

    v_check "Data Collection Endpoint (dce-spycloud-${WORKSPACE})" \
        az monitor data-collection endpoint show --name "dce-spycloud-${WORKSPACE}" -g "$RESOURCE_GROUP"

    v_check "Data Collection Rule (dcr-spycloud-${WORKSPACE})" \
        az monitor data-collection rule show --name "dcr-spycloud-${WORKSPACE}" -g "$RESOURCE_GROUP"

    v_check "Key Vault" \
        az keyvault list -g "$RESOURCE_GROUP" --query "[0].name"

    if $DEPLOY_PLAYBOOKS; then
        v_check "MDE Remediation Playbook" \
            az logic workflow show --name "SpyCloud-MDE-Remediation-${WORKSPACE}" -g "$RESOURCE_GROUP"
        v_check "CA Remediation Playbook" \
            az logic workflow show --name "SpyCloud-CA-Remediation-${WORKSPACE}" -g "$RESOURCE_GROUP"
    fi

    echo ""

    # Check Sentinel
    local ws_id
    ws_id=$(az monitor log-analytics workspace show --workspace-name "$WORKSPACE" -g "$RESOURCE_GROUP" --query id -o tsv 2>/dev/null || echo "")
    if [[ -n "$ws_id" ]]; then
        local sentinel
        sentinel=$(az resource list -g "$RESOURCE_GROUP" \
            --resource-type "Microsoft.OperationsManagement/solutions" \
            --query "[?contains(name,'SecurityInsights')].name" -o tsv 2>/dev/null || echo "")
        if [[ -n "$sentinel" ]]; then
            ok "Microsoft Sentinel enabled"
            ((v_pass++)) || true
        else
            warn "Sentinel may not be enabled yet"
            ((v_warn++)) || true
        fi
    fi

    # Check custom tables
    echo ""
    echo -e "  ${BOLD}Custom Tables${NC}"
    echo ""

    local expected_tables=("SpyCloudBreachWatchlist_CL" "SpyCloudBreachCatalog_CL" "Spycloud_MDE_Logs_CL" "SpyCloud_ConditionalAccessLogs_CL")
    for tbl in "${expected_tables[@]}"; do
        v_check "Table: ${tbl}" \
            az monitor log-analytics workspace table show --workspace-name "$WORKSPACE" -g "$RESOURCE_GROUP" --name "$tbl"
    done

    echo ""
    echo -e "  ${TEAL}+$(printf '─%.0s' $(seq 1 50))+${NC}"
    printf "  ${TEAL}|${NC}  ${GREEN}PASS: %-4d${NC} ${YELLOW}WARN: %-4d${NC} ${RED}FAIL: %-4d${NC}           ${TEAL}|${NC}\n" "$v_pass" "$v_warn" "$v_fail"
    echo -e "  ${TEAL}+$(printf '─%.0s' $(seq 1 50))+${NC}"
    echo ""

    # Also run the verify-deployment.sh if it exists
    if [[ -f "${SCRIPT_DIR}/verify-deployment.sh" ]]; then
        if prompt_yn "Run comprehensive verification script?" "n" 2>/dev/null; then
            echo ""
            bash "${SCRIPT_DIR}/verify-deployment.sh" -g "$RESOURCE_GROUP" -w "$WORKSPACE" || true
        fi
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 7: SUMMARY REPORT
# ═════════════════════════════════════════════════════════════════════════════

show_summary() {
    box_header "Phase 7/7 -- Deployment Summary" "$GREEN"

    local total_time
    total_time=$(elapsed)
    local sub_name
    sub_name=$(az account show --query name -o tsv 2>/dev/null || echo "unknown")

    # Portal URLs
    local portal="https://portal.azure.com"
    local sub_id
    sub_id=$(az account show --query id -o tsv 2>/dev/null)
    local sentinel_url="${portal}/#blade/Microsoft_Azure_Security_Insights/MainMenuBlade/0/subscriptionId/${sub_id}/resourceGroup/${RESOURCE_GROUP}/workspaceName/${WORKSPACE}"
    local connectors_url="${portal}/#blade/Microsoft_Azure_Security_Insights/DataConnectorsListBlade/subscriptionId/${sub_id}/resourceGroup/${RESOURCE_GROUP}/workspaceName/${WORKSPACE}"

    if [[ $TERM_COLORS -ge 256 ]]; then
        echo -e "  \033[38;2;0;180;216m  ____              ____ _                 _ ${NC}"
        echo -e "  \033[38;2;0;185;218m / ___| _ __  _   _/ ___| | ___  _   _  __| |${NC}"
        echo -e "  \033[38;2;0;190;220m \\___ \\| '_ \\| | | \\___ \\ |/ _ \\| | | |/ _\` |${NC}"
        echo -e "  \033[38;2;0;195;222m  ___) | |_) | |_| |___) | | (_) | |_| | (_| |${NC}"
        echo -e "  \033[38;2;0;200;224m |____/| .__/ \\__, |____/|_|\\___/ \\__,_|\\__,_|${NC}"
        echo -e "  \033[38;2;0;205;226m       |_|    |___/ ${NC}${BOLD}${GREEN}DEPLOYMENT COMPLETE${NC}"
    fi

    echo ""
    echo -e "  ${TEAL}$(printf '=%.0s' $(seq 1 64))${NC}"
    echo -e "  ${GREEN}${BOLD}  DEPLOYMENT SUCCESSFUL${NC}  ${DIM}|${NC}  ${DIM}Total time: ${total_time}${NC}"
    echo -e "  ${TEAL}$(printf '=%.0s' $(seq 1 64))${NC}"
    echo ""

    echo -e "  ${BOLD}Deployment Details${NC}"
    echo -e "  $(printf '%.0s-' $(seq 1 40))"
    echo -e "  ${DIM}Subscription:${NC}     ${BOLD}${sub_name}${NC}"
    echo -e "  ${DIM}Resource Group:${NC}   ${BOLD}${RESOURCE_GROUP}${NC}"
    echo -e "  ${DIM}Workspace:${NC}        ${BOLD}${WORKSPACE}${NC}"
    echo -e "  ${DIM}Region:${NC}           ${BOLD}${LOCATION}${NC}"
    echo -e "  ${DIM}Environment:${NC}      ${BOLD}${ENVIRONMENT}${NC}"
    echo -e "  ${DIM}Wizard Version:${NC}   ${DIM}v${WIZARD_VERSION}${NC}"
    echo ""

    echo -e "  ${BOLD}Results${NC}"
    echo -e "  $(printf '%.0s-' $(seq 1 40))"
    echo -e "  ${GREEN}Succeeded:${NC}  ${DEPLOY_SUCCESSES}"
    echo -e "  ${YELLOW}Warnings:${NC}   ${DEPLOY_WARNINGS}"
    echo -e "  ${RED}Errors:${NC}     ${DEPLOY_ERRORS}"
    echo ""

    echo -e "  ${BOLD}Resource URLs${NC}"
    echo -e "  $(printf '%.0s-' $(seq 1 40))"
    echo -e "  ${DIM}Sentinel:${NC}"
    echo -e "    ${CYAN}${sentinel_url}${NC}"
    echo ""
    echo -e "  ${DIM}Data Connectors:${NC}"
    echo -e "    ${CYAN}${connectors_url}${NC}"
    echo ""
    echo -e "  ${DIM}Config File:${NC}"
    echo -e "    ${CONFIG_FILE}"
    echo ""
    echo -e "  ${DIM}Deploy Log:${NC}"
    echo -e "    ${LOGFILE}"
    echo ""

    echo -e "  ${TEAL}$(printf '─%.0s' $(seq 1 64))${NC}"
    echo -e "  ${BOLD}Next Steps${NC}"
    echo -e "  ${TEAL}$(printf '─%.0s' $(seq 1 64))${NC}"
    echo ""
    echo -e "  ${CORAL}1.${NC}  Activate the SpyCloud data connector"
    echo -e "      ${DIM}Sentinel -> Data connectors -> SpyCloud -> Connect${NC}"
    echo ""
    echo -e "  ${CORAL}2.${NC}  Review and enable analytics rules"
    echo -e "      ${DIM}Sentinel -> Analytics -> filter 'SpyCloud' -> enable desired rules${NC}"
    echo ""
    echo -e "  ${CORAL}3.${NC}  Configure Entra ID diagnostic settings"
    echo -e "      ${DIM}Entra ID -> Monitoring -> Diagnostic settings -> Add${NC}"
    echo -e "      ${DIM}Check: SignInLogs, AuditLogs, RiskyUsers -> Send to ${WORKSPACE}${NC}"
    echo ""
    echo -e "  ${CORAL}4.${NC}  Grant admin consent for API permissions"
    echo -e "      ${DIM}Entra ID -> Enterprise Apps -> Managed Identities -> Grant consent${NC}"
    echo ""
    if $DEPLOY_COPILOT; then
        echo -e "  ${CORAL}5.${NC}  Upload Security Copilot files"
        echo -e "      ${DIM}Plugin: copilot/SpyCloud_Plugin.yaml -> Sources -> Custom${NC}"
        echo -e "      ${DIM}Agent:  copilot/SpyCloud_Agent.yaml  -> Build -> Upload YAML${NC}"
        echo ""
    fi
    echo -e "  ${CORAL}6.${NC}  Run comprehensive verification"
    echo -e "      ${DIM}./scripts/verify-deployment.sh -g ${RESOURCE_GROUP} -w ${WORKSPACE}${NC}"
    echo ""
    echo -e "  ${TEAL}$(printf '=%.0s' $(seq 1 64))${NC}"
    echo ""

    # Clean up state file on success
    if [[ $DEPLOY_ERRORS -eq 0 ]]; then
        rm -f "$STATE_FILE" 2>/dev/null || true
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# ERROR RECOVERY
# ═════════════════════════════════════════════════════════════════════════════

handle_deployment_error() {
    local failed_step="$1"
    save_state "$failed_step" "failed"

    echo ""
    echo -e "  ${RED}${BOLD}Deployment encountered an error at step: ${failed_step}${NC}"
    echo ""

    if ! $INTERACTIVE; then
        fail "Non-interactive mode -- cannot offer recovery options"
        info "State saved to ${STATE_FILE} for resume"
        info "Resume with: ./scripts/deploy-wizard.sh --resume"
        return 1
    fi

    echo -e "  ${BOLD}Recovery Options:${NC}"
    echo ""
    echo -e "    ${TEAL}[1]${NC}  Retry this step"
    echo -e "    ${TEAL}[2]${NC}  Skip and continue"
    echo -e "    ${TEAL}[3]${NC}  Save state and exit (resume later)"
    echo -e "    ${TEAL}[4]${NC}  Rollback (delete resource group) and exit"
    echo -e "    ${TEAL}[5]${NC}  Abort without rollback"
    echo ""
    echo -ne "  ${DIM}Choose recovery action${NC} ${DIM}[1]${NC}: "
    local recovery
    read -r recovery
    recovery="${recovery:-1}"

    case "$recovery" in
        1)
            info "Retrying step: ${failed_step}..."
            return 0  # Caller should retry
            ;;
        2)
            warn "Skipping failed step: ${failed_step}"
            return 0
            ;;
        3)
            info "State saved to ${STATE_FILE}"
            info "Resume with: ./scripts/deploy-wizard.sh --resume"
            exit 0
            ;;
        4)
            echo ""
            echo -e "  ${RED}${BOLD}WARNING: This will DELETE resource group '${RESOURCE_GROUP}' and ALL its resources.${NC}"
            if prompt_yn "Are you sure you want to rollback?" "n"; then
                info "Rolling back -- deleting resource group ${RESOURCE_GROUP}..."
                az group delete --name "$RESOURCE_GROUP" --yes --no-wait 2>>"$LOGFILE" || true
                ok "Rollback initiated (deletion is async)"
                rm -f "$STATE_FILE" 2>/dev/null || true
            else
                info "Rollback cancelled"
            fi
            exit 1
            ;;
        5)
            info "Aborting without rollback. State saved to ${STATE_FILE}"
            exit 1
            ;;
        *)
            warn "Invalid choice, retrying step..."
            return 0
            ;;
    esac
}

# ═════════════════════════════════════════════════════════════════════════════
# CONFIG MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════

load_config() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        fail "Config file not found: ${path}"
        return 1
    fi

    SUBSCRIPTION=$(jq -r '.subscription // empty' "$path" 2>/dev/null || echo "")
    RESOURCE_GROUP=$(jq -r '.resource_group // empty' "$path" 2>/dev/null || echo "")
    WORKSPACE=$(jq -r '.workspace // empty' "$path" 2>/dev/null || echo "")
    LOCATION=$(jq -r '.location // empty' "$path" 2>/dev/null || echo "")
    ENVIRONMENT=$(jq -r '.environment // "dev"' "$path" 2>/dev/null || echo "dev")
    DEPLOY_ANALYTICS=$(jq -r '.components.analytics // true' "$path" 2>/dev/null || echo "true")
    DEPLOY_PLAYBOOKS=$(jq -r '.components.playbooks // true' "$path" 2>/dev/null || echo "true")
    DEPLOY_WORKBOOKS=$(jq -r '.components.workbooks // true' "$path" 2>/dev/null || echo "true")
    DEPLOY_NOTEBOOKS=$(jq -r '.components.notebooks // false' "$path" 2>/dev/null || echo "false")
    DEPLOY_COPILOT=$(jq -r '.components.copilot // false' "$path" 2>/dev/null || echo "false")
    TEMPLATE_URL=$(jq -r '.template_url // empty' "$path" 2>/dev/null || echo "")

    ok "Loaded config from ${DIM}${path}${NC}"
}

validate_config() {
    local errors=0

    if [[ -z "$RESOURCE_GROUP" ]]; then
        fail "Resource group not specified (--resource-group or config)"
        ((errors++))
    fi
    if [[ -z "$WORKSPACE" ]]; then
        fail "Workspace not specified (--workspace or config)"
        ((errors++))
    fi
    if [[ -z "$SPYCLOUD_API_KEY" ]]; then
        fail "API key not specified (--api-key or SPYCLOUD_API_KEY env)"
        ((errors++))
    fi

    LOCATION="${LOCATION:-eastus}"
    SUBSCRIPTION="${SUBSCRIPTION:-$(az account show --query id -o tsv 2>/dev/null || echo "")}"

    if [[ $errors -gt 0 ]]; then
        echo ""
        fail "${errors} required parameter(s) missing"
        info "For non-interactive mode, provide: --resource-group, --workspace, --api-key"
        info "Or use a config file: --config .spycloud-config.json"
        exit 1
    fi
}

load_resume_state() {
    if [[ ! -f "$STATE_FILE" ]]; then
        fail "No saved state found at ${STATE_FILE}"
        exit 1
    fi

    RESOURCE_GROUP=$(jq -r '.resource_group // empty' "$STATE_FILE" 2>/dev/null)
    WORKSPACE=$(jq -r '.workspace // empty' "$STATE_FILE" 2>/dev/null)
    LOCATION=$(jq -r '.location // empty' "$STATE_FILE" 2>/dev/null)
    SUBSCRIPTION=$(jq -r '.subscription // empty' "$STATE_FILE" 2>/dev/null)

    local last_step
    last_step=$(jq -r '.last_completed_step // ""' "$STATE_FILE" 2>/dev/null)
    ok "Resuming from step: ${BOLD}${last_step}${NC}"
}

# ═════════════════════════════════════════════════════════════════════════════
# CLI ARGUMENT PARSING
# ═════════════════════════════════════════════════════════════════════════════

show_help() {
    show_banner
    echo -e "  ${BOLD}USAGE${NC}"
    echo -e "    $0 [OPTIONS]"
    echo ""
    echo -e "  ${BOLD}OPTIONS${NC}"
    echo -e "    ${TEAL}-g, --resource-group${NC} NAME    Resource group name"
    echo -e "    ${TEAL}-w, --workspace${NC} NAME         Log Analytics workspace name"
    echo -e "    ${TEAL}-k, --api-key${NC} KEY            SpyCloud API key"
    echo -e "    ${TEAL}-l, --location${NC} REGION        Azure region (default: eastus)"
    echo -e "    ${TEAL}-s, --subscription${NC} ID        Azure subscription ID"
    echo -e "    ${TEAL}-e, --environment${NC} ENV        Environment tag (dev/staging/prod)"
    echo -e "    ${TEAL}    --config${NC} FILE            Load configuration from JSON file"
    echo -e "    ${TEAL}    --non-interactive${NC}         Run without prompts (CI/CD mode)"
    echo -e "    ${TEAL}    --resume${NC}                  Resume a previously failed deployment"
    echo -e "    ${TEAL}    --template${NC} URL            Custom ARM template URL or path"
    echo -e "    ${TEAL}    --no-analytics${NC}            Skip analytics rules deployment"
    echo -e "    ${TEAL}    --no-playbooks${NC}            Skip playbooks deployment"
    echo -e "    ${TEAL}    --no-workbooks${NC}            Skip workbooks deployment"
    echo -e "    ${TEAL}    --with-notebooks${NC}          Include Jupyter notebooks"
    echo -e "    ${TEAL}    --with-copilot${NC}            Include Security Copilot plugin"
    echo -e "    ${TEAL}-h, --help${NC}                    Show this help"
    echo ""
    echo -e "  ${BOLD}EXAMPLES${NC}"
    echo ""
    echo -e "    ${DIM}# Fully interactive wizard:${NC}"
    echo -e "    ./scripts/deploy-wizard.sh"
    echo ""
    echo -e "    ${DIM}# Non-interactive with config file:${NC}"
    echo -e "    ./scripts/deploy-wizard.sh --non-interactive --config .spycloud-config.json -k \$API_KEY"
    echo ""
    echo -e "    ${DIM}# Non-interactive with all args:${NC}"
    echo -e "    ./scripts/deploy-wizard.sh --non-interactive -g my-rg -w my-ws -k KEY -l eastus"
    echo ""
    echo -e "    ${DIM}# Resume a failed deployment:${NC}"
    echo -e "    ./scripts/deploy-wizard.sh --resume -k \$API_KEY"
    echo ""
    echo -e "    ${DIM}# CI/CD pipeline:${NC}"
    echo -e "    export SPYCLOUD_API_KEY=\$SECRET"
    echo -e "    ./scripts/deploy-wizard.sh --non-interactive --config .spycloud-config.json"
    echo ""
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -g|--resource-group) RESOURCE_GROUP="$2"; shift 2;;
            -w|--workspace) WORKSPACE="$2"; shift 2;;
            -k|--api-key) SPYCLOUD_API_KEY="$2"; shift 2;;
            -l|--location) LOCATION="$2"; shift 2;;
            -s|--subscription) SUBSCRIPTION="$2"; shift 2;;
            -e|--environment) ENVIRONMENT="$2"; shift 2;;
            --config) CONFIG_PATH="$2"; shift 2;;
            --non-interactive) INTERACTIVE=false; shift;;
            --resume) RESUME=true; shift;;
            --template) TEMPLATE_URL="$2"; shift 2;;
            --no-analytics) DEPLOY_ANALYTICS=false; shift;;
            --no-playbooks) DEPLOY_PLAYBOOKS=false; shift;;
            --no-workbooks) DEPLOY_WORKBOOKS=false; shift;;
            --with-notebooks) DEPLOY_NOTEBOOKS=true; shift;;
            --with-copilot) DEPLOY_COPILOT=true; shift;;
            -h|--help) show_help;;
            *) echo -e "${RED}Unknown option: $1${NC}"; echo "Run with --help for usage."; exit 1;;
        esac
    done

    # Pick up API key from environment if not set via CLI
    if [[ -z "$SPYCLOUD_API_KEY" ]]; then
        SPYCLOUD_API_KEY="${SPYCLOUD_API_KEY:-${SPYCLOUD_API_KEY_ENV:-}}"
    fi
    SPYCLOUD_API_KEY="${SPYCLOUD_API_KEY:-${SPYCLOUD_API_KEY:+}}"
    # Final fallback to environment variable
    if [[ -z "$SPYCLOUD_API_KEY" ]]; then
        SPYCLOUD_API_KEY="${SPYCLOUD_API_KEY:-}"
    fi

    # Load config file if specified
    if [[ -n "$CONFIG_PATH" ]]; then
        load_config "$CONFIG_PATH"
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

main() {
    parse_args "$@"

    # Initialize log
    mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null || true
    echo "SpyCloud Sentinel Deploy Wizard v${WIZARD_VERSION}" > "$LOGFILE"
    echo "Started: $(date -Iseconds)" >> "$LOGFILE"
    echo "Arguments: $*" >> "$LOGFILE"
    echo "---" >> "$LOGFILE"

    # Trap for cleanup
    trap 'tput cnorm 2>/dev/null; echo ""' EXIT

    # Show banner
    show_banner

    # Handle resume mode
    if $RESUME; then
        load_resume_state
        if [[ -z "$SPYCLOUD_API_KEY" ]]; then
            if $INTERACTIVE; then
                prompt_input "SpyCloud API key (needed for resume)" "" SPYCLOUD_API_KEY true
            else
                fail "API key required for resume. Pass via --api-key or SPYCLOUD_API_KEY env."
                exit 1
            fi
        fi
    fi

    # Phase 1: Prerequisites
    check_prerequisites

    # Phase 2: Configuration
    configure_deployment

    # Phase 3: Save config
    generate_config

    # Phase 4: Show plan and confirm
    show_deployment_plan

    # Phase 5: Deploy
    execute_deployment

    # Phase 6: Validate
    run_validation

    # Phase 7: Summary
    show_summary

    echo -e "  ${DIM}Thank you for using SpyCloud Sentinel Deploy Wizard.${NC}"
    echo ""
}

# Run main with all arguments
main "$@"
