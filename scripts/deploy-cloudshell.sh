#!/usr/bin/env bash
#===============================================================================
#  SpyCloud Sentinel — Azure Cloud Shell Deployment Launcher
#  Version: 13.12.0
#
#  Fully automated deployment for Azure Cloud Shell.
#  Clones the repo, detects environment, and runs guided or unattended setup.
#
#  Quick start (paste into Cloud Shell):
#    curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-cloudshell.sh | bash
#
#  With answer file (unattended):
#    curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/deploy-cloudshell.sh | bash -s -- --answer-file ./answers.json
#===============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

REPO_URL="https://github.com/iammrherb/SPYCLOUD-SENTINEL.git"
REPO_DIR="${HOME}/spycloud-sentinel"
VERSION="13.12.0"
ANSWER_FILE=""
LOG_FILE="/tmp/spycloud-deploy-$(date +%Y%m%d-%H%M%S).log"
OPT_RG="" ; OPT_WS="" ; OPT_KEY="" ; OPT_LOC="" ; OPT_CLOUD=""
RG="" ; WS="" ; API_KEY="" ; LOCATION="eastus" ; CREATE_RG=false

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "============================================================"
  echo "     SpyCloud Identity Exposure Intelligence for Sentinel — Cloud Shell Deployer"
  echo "                   Version ${VERSION}"
  echo "============================================================"
  echo -e "${NC}"
}

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "  ${GREEN}[OK]${NC} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "  ${RED}[ERR]${NC} $*" | tee -a "$LOG_FILE"; }
step() { echo -e "\n${BLUE}${BOLD}--- $* ---${NC}" | tee -a "$LOG_FILE"; }

usage() {
  cat << EOF
Usage: deploy-cloudshell.sh [OPTIONS]

Options:
  -a, --answer-file FILE   JSON answer file for unattended deployment
  -g, --resource-group RG  Target resource group name
  -w, --workspace WS       Log Analytics workspace name
  -k, --api-key KEY        SpyCloud Enterprise API key
  -l, --location LOC       Azure region (default: eastus)
  -c, --cloud CLOUD        Azure cloud: AzureCloud | AzureUSGovernment
      --generate-answers   Generate answer file template
  -h, --help               Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --answer-file|-a) ANSWER_FILE="$2"; shift 2;;
    --resource-group|-g) OPT_RG="$2"; shift 2;;
    --workspace|-w) OPT_WS="$2"; shift 2;;
    --api-key|-k) OPT_KEY="$2"; shift 2;;
    --location|-l) OPT_LOC="$2"; shift 2;;
    --cloud|-c) OPT_CLOUD="$2"; shift 2;;
    --generate-answers)
      cat << 'ANSEOF'
{
  "resourceGroup": "rg-spycloud-sentinel",
  "workspace": "spycloud-sentinel-ws",
  "apiKey": "YOUR_SPYCLOUD_ENTERPRISE_API_KEY",
  "location": "eastus",
  "features": {
    "enableMDE": true,
    "enableConditionalAccess": true,
    "enableCompass": true,
    "enableSIP": true,
    "enableInvestigations": false,
    "enableIdLink": false,
    "enableKeyVault": true,
    "enableFunctionApp": true,
    "createNewWorkspace": true,
    "enableAnalyticsRules": true
  }
}
ANSEOF
      exit 0;;
    --help|-h) usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 1;;
  esac
done

# Phase 1: Environment Detection
detect_environment() {
  step "Phase 1: Environment Detection"

  if [[ -n "${AZURE_HTTP_USER_AGENT:-}" ]] || [[ -d "/home/${USER:-root}/clouddrive" ]]; then
    ok "Running in Azure Cloud Shell"
    IS_CLOUDSHELL=true
  else
    warn "Not in Cloud Shell — running in standalone mode"
    IS_CLOUDSHELL=false
  fi

  if ! command -v az &>/dev/null; then
    err "Azure CLI (az) not found. Install: https://aka.ms/installazurecli"
    exit 1
  fi
  ok "Azure CLI found"

  ACCOUNT=$(az account show --query '{name:name, id:id, cloud:environmentName}' -o json 2>/dev/null || true)
  if [[ -z "$ACCOUNT" || "$ACCOUNT" == "null" ]]; then
    if [[ "$IS_CLOUDSHELL" == true ]]; then
      err "Not logged in. Cloud Shell should auto-authenticate."
      exit 1
    else
      log "Not logged in. Running az login..."
      az login
      ACCOUNT=$(az account show --query '{name:name, id:id, cloud:environmentName}' -o json)
    fi
  fi

  CLOUD_ENV=$(echo "$ACCOUNT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('cloud','AzureCloud'))")
  SUB_NAME=$(echo "$ACCOUNT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('name','?'))")
  SUB_ID=$(echo "$ACCOUNT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id','?'))")
  ok "Cloud: ${CLOUD_ENV}"
  ok "Subscription: ${SUB_NAME} (${SUB_ID})"

  for tool in python3 git jq; do
    if command -v "$tool" &>/dev/null; then
      ok "$tool available"
    else
      warn "$tool not found"
    fi
  done
}

# Phase 2: Clone Repo
clone_repo() {
  step "Phase 2: Repository Setup"

  if [[ -d "$REPO_DIR/.git" ]]; then
    log "Repository exists at $REPO_DIR — pulling latest..."
    cd "$REPO_DIR"
    git pull origin main 2>/dev/null || true
    ok "Repository updated"
  else
    log "Cloning SpyCloud Sentinel..."
    git clone "$REPO_URL" "$REPO_DIR" 2>&1 | tail -1
    cd "$REPO_DIR"
    ok "Repository cloned to $REPO_DIR"
  fi

  for f in azuredeploy.json createUiDefinition.json scripts/deploy-all.sh; do
    [[ -f "$f" ]] && ok "Found: $f" || { err "Missing: $f"; exit 1; }
  done
}

# Phase 3: Configuration
load_config() {
  step "Phase 3: Configuration"

  if [[ -n "$ANSWER_FILE" && -f "$ANSWER_FILE" ]]; then
    log "Loading from answer file: $ANSWER_FILE"
    RG=$(python3 -c "import json; print(json.load(open('$ANSWER_FILE')).get('resourceGroup',''))" 2>/dev/null)
    WS=$(python3 -c "import json; print(json.load(open('$ANSWER_FILE')).get('workspace',''))" 2>/dev/null)
    API_KEY=$(python3 -c "import json; print(json.load(open('$ANSWER_FILE')).get('apiKey',''))" 2>/dev/null)
    LOCATION=$(python3 -c "import json; print(json.load(open('$ANSWER_FILE')).get('location','eastus'))" 2>/dev/null)
    ok "Answer file loaded"
  fi

  RG="${OPT_RG:-${RG:-}}"
  WS="${OPT_WS:-${WS:-}}"
  API_KEY="${OPT_KEY:-${API_KEY:-}}"
  LOCATION="${OPT_LOC:-${LOCATION:-eastus}}"

  if [[ -z "$RG" ]]; then
    echo ""
    echo -e "${BOLD}Resource Group:${NC}"
    echo "  1) Create new resource group"
    echo "  2) Use existing resource group"
    read -rp "  Choice [1-2]: " rg_choice
    if [[ "$rg_choice" == "1" ]]; then
      read -rp "  New resource group name: " RG
      CREATE_RG=true
    else
      echo "  Existing resource groups:"
      az group list --query "[].name" -o tsv 2>/dev/null | head -20 | while read -r g; do echo "    - $g"; done
      read -rp "  Resource group name: " RG
    fi
  fi

  if [[ -z "$WS" ]]; then
    read -rp "  Workspace name [spycloud-sentinel-ws]: " WS
    WS="${WS:-spycloud-sentinel-ws}"
  fi

  if [[ -z "$API_KEY" ]]; then
    echo -e "${BOLD}SpyCloud Enterprise API Key:${NC} (get at https://portal.spycloud.com)"
    read -rsp "  API Key: " API_KEY; echo ""
  fi

  [[ -z "$API_KEY" ]] && { err "API key required"; exit 1; }

  ok "Config: RG=$RG WS=$WS Location=$LOCATION Cloud=$CLOUD_ENV"
}

# Phase 4: Deploy
deploy() {
  step "Phase 4: Deployment"

  if [[ "$CREATE_RG" == true ]]; then
    log "Creating resource group: $RG in $LOCATION"
    az group create --name "$RG" --location "$LOCATION" -o none
    ok "Resource group created"
  fi

  log "Validating ARM template..."
  az deployment group validate \
    --resource-group "$RG" \
    --template-file azuredeploy.json \
    --parameters workspace="$WS" spycloudApiKey="$API_KEY" \
    --no-prompt -o none 2>&1 || { err "Validation failed"; exit 1; }
  ok "Validation passed"

  DEPLOY_NAME="spycloud-cs-$(date +%Y%m%d-%H%M%S)"
  log "Deploying $DEPLOY_NAME (this may take 5-10 min)..."

  if az deployment group create \
    --name "$DEPLOY_NAME" \
    --resource-group "$RG" \
    --template-file azuredeploy.json \
    --parameters workspace="$WS" spycloudApiKey="$API_KEY" \
    --mode Incremental --no-prompt -o none 2>&1 | tee -a "$LOG_FILE"; then
    ok "Deployment succeeded!"
  else
    err "Deployment failed!"
    echo ""
    az deployment group show --name "$DEPLOY_NAME" -g "$RG" \
      --query "properties.error" -o json 2>/dev/null || true

    echo ""
    read -rp "Clean up failed deployment? [y/N]: " retry
    if [[ "$retry" =~ ^[Yy] ]]; then
      az deployment group delete --name "$DEPLOY_NAME" -g "$RG" --no-wait 2>/dev/null || true
      log "Cleanup initiated"
    fi
    exit 1
  fi
}

# Phase 5: Post-Deploy
post_deploy() {
  step "Phase 5: Post-Deployment"

  log "Verifying deployment..."
  WS_ID=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query customerId -o tsv 2>/dev/null || echo "")
  if [[ -n "$WS_ID" ]]; then
    TABLES=$(az monitor log-analytics workspace table list -g "$RG" --workspace-name "$WS" \
      --query "[?contains(name,'SpyCloud')].name" -o tsv 2>/dev/null | wc -l)
    ok "SpyCloud tables: $TABLES"
  fi

  PLAYBOOKS=$(az logic workflow list -g "$RG" --query "[?contains(name,'SpyCloud')].name" -o tsv 2>/dev/null | wc -l)
  ok "Logic App playbooks: $PLAYBOOKS"

  echo ""
  echo -e "${GREEN}${BOLD}============================================================${NC}"
  echo -e "${GREEN}${BOLD}  Deployment Complete!${NC}"
  echo -e "${GREEN}${BOLD}============================================================${NC}"
  echo ""
  echo "  Next Steps:"
  echo "  1. Sentinel > Data Connectors > SpyCloud > Open connector page"
  echo "  2. Add API keys and click Connect"
  echo "  3. Analytics > Rule Templates > filter 'SpyCloud' > enable"
  echo "  4. Verify: SpyCloudBreachWatchlist_CL | take 10"
  echo ""
  echo "  Run QA tests:"
  echo "  curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/spycloud-qa.sh | bash"
  echo ""
  echo "  Log: $LOG_FILE"
}

main() {
  banner
  detect_environment
  clone_repo
  load_config
  deploy
  post_deploy
  log "Done!"
}

main "$@"
