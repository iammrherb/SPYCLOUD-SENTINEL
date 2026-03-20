#!/usr/bin/env bash
#===============================================================================
#  SpyCloud Sentinel — Sentinel Graph & MCP Tools Setup
#  Version: 1.0.0
#
#  Automates the setup of:
#    1. Microsoft Sentinel Custom Graphs for SpyCloud identity data
#    2. Sentinel Graph MCP Server integration for AI-powered analysis
#    3. VS Code extension configuration
#    4. Graph materialization scheduling
#
#  Prerequisites:
#    - Azure CLI authenticated (az login)
#    - Microsoft Sentinel data lake onboarded
#    - Security Operator or Security Administrator role
#    - VS Code with Microsoft Sentinel extension (for notebook workflows)
#
#  Usage:
#    ./scripts/setup-sentinel-graph.sh -g <resource-group> -w <workspace>
#    ./scripts/setup-sentinel-graph.sh --generate-notebook
#===============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
step() { echo -e "\n${MAGENTA}${BOLD}=== $1 ===${NC}"; }

RG=""; WS=""; MODE="setup"; OUTPUT_DIR="."

while [[ $# -gt 0 ]]; do
  case $1 in
    -g|--resource-group) RG="$2"; shift 2;;
    -w|--workspace) WS="$2"; shift 2;;
    -o|--output-dir) OUTPUT_DIR="$2"; shift 2;;
    --generate-notebook) MODE="notebook"; shift;;
    --generate-mcp-config) MODE="mcp-config"; shift;;
    --validate) MODE="validate"; shift;;
    -h|--help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  -g, --resource-group    Azure resource group"
      echo "  -w, --workspace         Log Analytics workspace name"
      echo "  -o, --output-dir        Output directory for generated files (default: .)"
      echo "  --generate-notebook     Generate SpyCloud identity graph notebook"
      echo "  --generate-mcp-config   Generate VS Code MCP server configuration"
      echo "  --validate              Validate graph prerequisites and permissions"
      echo "  -h, --help              Show this help"
      exit 0;;
    *) shift;;
  esac
done

banner() {
  echo ""
  echo -e "${BOLD}============================================================${NC}"
  echo -e "${BOLD}  SpyCloud Sentinel — Graph & MCP Tools Setup              ${NC}"
  echo -e "${BOLD}============================================================${NC}"
}

# ==============================================================================
# VALIDATE PREREQUISITES
# ==============================================================================
validate_prerequisites() {
  step "Validating Prerequisites"

  # Azure CLI
  if ! az account show &>/dev/null; then
    fail "Not logged in. Run: az login"
    return 1
  fi
  ok "Azure CLI authenticated"

  local sub_name=$(az account show --query name -o tsv)
  info "Subscription: $sub_name"

  # Workspace
  if [[ -n "$RG" && -n "$WS" ]]; then
    local ws_id=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query id -o tsv 2>/dev/null)
    if [[ -n "$ws_id" ]]; then
      ok "Workspace found: $WS"
    else
      fail "Workspace not found: $WS in $RG"
      return 1
    fi
  fi

  # Check permissions
  local upn=$(az ad signed-in-user show --query userPrincipalName -o tsv 2>/dev/null)
  if [[ -n "$upn" ]]; then
    info "Signed in as: $upn"

    # Check for Security roles
    local roles=$(az role assignment list --assignee "$upn" --query "[].roleDefinitionName" -o tsv 2>/dev/null | sort -u | tr '\n' ', ')
    if [[ -n "$roles" ]]; then
      info "Roles: $roles"
      if echo "$roles" | grep -qi "security\|admin\|operator"; then
        ok "Has security role for graph operations"
      else
        warn "May need Security Operator or Security Administrator role for graph materialization"
      fi
    fi
  fi

  # Check Sentinel data lake status
  if [[ -n "$RG" && -n "$WS" ]]; then
    local ws_id=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query id -o tsv 2>/dev/null)
    local sentinel_check=$(az rest --method GET \
      --uri "${ws_id}/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2023-02-01" \
      2>/dev/null)
    if [[ $? -eq 0 && -n "$sentinel_check" ]]; then
      ok "Sentinel enabled on workspace"
    else
      warn "Could not verify Sentinel status - ensure data lake is onboarded"
    fi
  fi

  # Check SpyCloud tables exist
  if [[ -n "$RG" && -n "$WS" ]]; then
    local spycloud_tables=0
    for table in SpyCloudBreachWatchlist_CL SpyCloudCompassDevices_CL SpyCloudSipCookies_CL SpyCloudIdLink_CL; do
      if az monitor log-analytics workspace table show -g "$RG" -w "$WS" -n "$table" &>/dev/null; then
        spycloud_tables=$((spycloud_tables + 1))
      fi
    done
    if [[ $spycloud_tables -gt 0 ]]; then
      ok "SpyCloud tables found: $spycloud_tables/4 key tables"
    else
      warn "No SpyCloud tables found - deploy SpyCloud Sentinel first"
    fi
  fi
}

# ==============================================================================
# GENERATE SPYCLOUD IDENTITY GRAPH NOTEBOOK
# ==============================================================================
generate_notebook() {
  step "Generating SpyCloud Identity Graph Notebook"

  local notebook_path="${OUTPUT_DIR}/SpyCloud-Identity-Graph.ipynb"
  local workspace_placeholder="${WS:-<YourWorkspaceName>}"

  python3 << 'PYEOF' - "$notebook_path" "$workspace_placeholder"
import json
import sys

notebook_path = sys.argv[1]
workspace = sys.argv[2]

notebook = {
    "nbformat": 4,
    "nbformat_minor": 5,
    "metadata": {
        "kernelspec": {
            "display_name": "Microsoft Sentinel (Spark)",
            "language": "python",
            "name": "sentinel_spark"
        },
        "language_info": {
            "name": "python",
            "version": "3.10.0"
        },
        "description": "SpyCloud Identity Exposure Graph - Models identity relationships, credential exposures, device infections, and attack paths using Microsoft Sentinel Custom Graphs.",
        "authors": [{"name": "SpyCloud Integration Team"}]
    },
    "cells": [
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "# SpyCloud Identity Exposure Graph\n",
                "\n",
                "This notebook creates a custom Sentinel graph that models SpyCloud identity exposure data.\n",
                "It builds a graph with the following structure:\n",
                "\n",
                "**Node Types:**\n",
                "- `User` - Exposed identities from SpyCloud watchlist data\n",
                "- `Device` - Infected devices from SpyCloud Compass\n",
                "- `Application` - Compromised applications (VPN, SSO, cloud apps)\n",
                "- `Breach` - Breach sources from SpyCloud catalog\n",
                "- `MalwareFamily` - Infostealer malware families (RedLine, Vidar, etc.)\n",
                "\n",
                "**Edge Types:**\n",
                "- `exposed_in` - User was exposed in a breach\n",
                "- `infected_by` - Device was infected by malware\n",
                "- `has_stolen_creds_for` - User has stolen credentials for an application\n",
                "- `linked_to` - Identity linkage between personas\n",
                "- `remediated_by` - Remediation actions taken\n",
                "\n",
                "## Prerequisites\n",
                "1. Microsoft Sentinel data lake onboarded\n",
                "2. SpyCloud Sentinel deployed with data flowing\n",
                "3. VS Code with Microsoft Sentinel extension\n",
                "4. Security Operator or Security Administrator role\n",
                "\n",
                "## Setup\n",
                "1. Open this notebook in VS Code with Microsoft Sentinel extension\n",
                "2. Select kernel: **Microsoft Sentinel** > **Medium graph pool**\n",
                "3. Update the workspace name in Cell 2\n",
                "4. Run all cells sequentially"
            ]
        },
        {
            "cell_type": "code",
            "metadata": {"tags": ["setup"]},
            "source": [
                "# Cell 1: Verify environment and library version\n",
                "import pkg_resources\n",
                "import logging\n",
                "\n",
                "version = pkg_resources.get_distribution('MicrosoftSentinelGraphProvider').version\n",
                "print(f'MicrosoftSentinelGraphProvider: {version}')\n",
                "print(f'Pool: {spark.conf.get(\"spark.synapse.pool.name\")}')\n",
                "print(f'Region: {spark.conf.get(\"spark.cluster.region\")}')\n",
                "print(f'Account: {spark.conf.get(\"spark.pjs.account.id\")}')\n",
                "\n",
                "logging.getLogger('sentinel_graph').setLevel(logging.INFO)"
            ],
            "outputs": [],
            "execution_count": None
        },
        {
            "cell_type": "code",
            "metadata": {"tags": ["data-load"]},
            "source": [
                "# Cell 2: Load SpyCloud data from Sentinel data lake\n",
                "from sentinel_lake.providers import MicrosoftSentinelProvider\n",
                "from pyspark.sql.functions import col, count, lit, coalesce, first, max as spark_max, expr, lower, trim\n",
                "\n",
                f"WORKSPACE = '{workspace}'\n",
                "\n",
                "sentinel = MicrosoftSentinelProvider(spark)\n",
                "\n",
                "# Load SpyCloud exposure data (last 30 days)\n",
                "watchlist_df = (\n",
                "    sentinel.read_table('SpyCloudBreachWatchlist_CL', WORKSPACE)\n",
                "    .filter(col('TimeGenerated') >= expr('current_timestamp() - INTERVAL 30 DAYS'))\n",
                "    .filter(col('email').isNotNull())\n",
                "    .select('email', 'severity', 'source_id', 'password_plaintext',\n",
                "            'password_type', 'infected_machine_id', 'infected_path',\n",
                "            'sighting', 'breach_title', 'malware_family', 'TimeGenerated')\n",
                ").persist()\n",
                "\n",
                "# Load device data\n",
                "devices_df = (\n",
                "    sentinel.read_table('SpyCloudCompassDevices_CL', WORKSPACE)\n",
                "    .filter(col('TimeGenerated') >= expr('current_timestamp() - INTERVAL 30 DAYS'))\n",
                "    .filter(col('user_hostname').isNotNull())\n",
                "    .select('user_hostname', 'user_os', 'user_browser', 'infected_machine_id',\n",
                "            'malware_family', 'email', 'TimeGenerated')\n",
                "    .dropDuplicates(['user_hostname', 'infected_machine_id'])\n",
                ").persist()\n",
                "\n",
                "# Load application credentials\n",
                "compass_df = (\n",
                "    sentinel.read_table('SpyCloudCompassData_CL', WORKSPACE)\n",
                "    .filter(col('TimeGenerated') >= expr('current_timestamp() - INTERVAL 30 DAYS'))\n",
                "    .filter(col('target_domain').isNotNull())\n",
                "    .select('email', 'target_domain', 'target_url', 'password_type',\n",
                "            'malware_family', 'severity', 'TimeGenerated')\n",
                ").persist()\n",
                "\n",
                "# Load breach catalog\n",
                "catalog_df = (\n",
                "    sentinel.read_table('SpyCloudBreachCatalog_CL', WORKSPACE)\n",
                "    .filter(col('id').isNotNull())\n",
                "    .select('id', 'title', 'type', 'num_records', 'confidence',\n",
                "            'acquisition_date', 'malware_family')\n",
                "    .dropDuplicates(['id'])\n",
                ").persist()\n",
                "\n",
                "# Load identity links\n",
                "idlink_df = (\n",
                "    sentinel.read_table('SpyCloudIdLink_CL', WORKSPACE)\n",
                "    .filter(col('TimeGenerated') >= expr('current_timestamp() - INTERVAL 30 DAYS'))\n",
                "    .select('source_email', 'target_email', 'link_type', 'confidence', 'TimeGenerated')\n",
                ").persist()\n",
                "\n",
                "# Load Entra ID users for enrichment\n",
                "try:\n",
                "    entra_users_df = (\n",
                "        sentinel.read_table('IdentityInfo')\n",
                "        .filter(col('TimeGenerated') >= expr('current_timestamp() - INTERVAL 14 DAYS'))\n",
                "        .select('AccountUPN', 'AccountDisplayName', 'Department', 'JobTitle',\n",
                "                'Country', 'City', 'IsAccountEnabled')\n",
                "        .dropDuplicates(['AccountUPN'])\n",
                "    ).persist()\n",
                "    print(f'Loaded IdentityInfo: {entra_users_df.count()} users')\n",
                "except Exception as e:\n",
                "    print(f'IdentityInfo not available: {e}')\n",
                "    entra_users_df = None\n",
                "\n",
                "# Load MDE remediation logs\n",
                "try:\n",
                "    mde_logs_df = (\n",
                "        sentinel.read_table('Spycloud_MDE_Logs_CL', WORKSPACE)\n",
                "        .filter(col('TimeGenerated') >= expr('current_timestamp() - INTERVAL 30 DAYS'))\n",
                "        .select('Email', 'DeviceId', 'DeviceName', 'Action', 'ActionStatus', 'TimeGenerated')\n",
                "    ).persist()\n",
                "    print(f'Loaded MDE logs: {mde_logs_df.count()} actions')\n",
                "except Exception as e:\n",
                "    print(f'MDE logs not available: {e}')\n",
                "    mde_logs_df = None\n",
                "\n",
                "print(f'Watchlist: {watchlist_df.count()} exposures')\n",
                "print(f'Devices: {devices_df.count()} infected devices')\n",
                "print(f'Compass: {compass_df.count()} app credentials')\n",
                "print(f'Catalog: {catalog_df.count()} breach sources')\n",
                "print(f'IdLink: {idlink_df.count()} identity links')"
            ],
            "outputs": [],
            "execution_count": None
        },
        {
            "cell_type": "code",
            "metadata": {"tags": ["nodes"]},
            "source": [
                "# Cell 3: Build node DataFrames\n",
                "\n",
                "# User nodes - exposed identities\n",
                "user_nodes_df = (\n",
                "    watchlist_df\n",
                "    .groupBy('email')\n",
                "    .agg(\n",
                "        spark_max('severity').alias('max_severity'),\n",
                "        count('*').alias('exposure_count'),\n",
                "        first('TimeGenerated').alias('first_seen')\n",
                "    )\n",
                "    .withColumn('nodeType', lit('User'))\n",
                ")\n",
                "\n",
                "# Enrich with Entra ID data if available\n",
                "if entra_users_df is not None:\n",
                "    user_nodes_df = (\n",
                "        user_nodes_df\n",
                "        .join(entra_users_df, user_nodes_df.email == entra_users_df.AccountUPN, 'left')\n",
                "        .select(\n",
                "            'email', 'max_severity', 'exposure_count', 'first_seen', 'nodeType',\n",
                "            coalesce(col('AccountDisplayName'), col('email')).alias('display_name'),\n",
                "            coalesce(col('Department'), lit('Unknown')).alias('department'),\n",
                "            coalesce(col('JobTitle'), lit('Unknown')).alias('job_title'),\n",
                "            coalesce(col('Country'), lit('Unknown')).alias('country'),\n",
                "            coalesce(col('IsAccountEnabled'), lit(True)).alias('account_enabled')\n",
                "        )\n",
                "    )\n",
                "else:\n",
                "    user_nodes_df = user_nodes_df.withColumn('display_name', col('email'))\n",
                "\n",
                "# Device nodes - infected machines\n",
                "device_nodes_df = (\n",
                "    devices_df\n",
                "    .groupBy('user_hostname')\n",
                "    .agg(\n",
                "        first('user_os').alias('os'),\n",
                "        first('user_browser').alias('browser'),\n",
                "        count('*').alias('infection_count'),\n",
                "        first('malware_family').alias('primary_malware')\n",
                "    )\n",
                "    .withColumn('nodeType', lit('Device'))\n",
                ")\n",
                "\n",
                "# Application nodes - compromised apps\n",
                "app_nodes_df = (\n",
                "    compass_df\n",
                "    .groupBy('target_domain')\n",
                "    .agg(\n",
                "        count('*').alias('stolen_cred_count'),\n",
                "        spark_max('severity').alias('max_severity')\n",
                "    )\n",
                "    .withColumn('nodeType', lit('Application'))\n",
                ")\n",
                "\n",
                "# Breach source nodes\n",
                "breach_nodes_df = (\n",
                "    catalog_df\n",
                "    .select(\n",
                "        col('id').alias('breach_id'),\n",
                "        col('title').alias('breach_title'),\n",
                "        col('type').alias('breach_type'),\n",
                "        col('num_records'),\n",
                "        col('confidence')\n",
                "    )\n",
                "    .withColumn('nodeType', lit('Breach'))\n",
                ")\n",
                "\n",
                "# Malware family nodes\n",
                "malware_nodes_df = (\n",
                "    watchlist_df\n",
                "    .filter(col('malware_family').isNotNull())\n",
                "    .groupBy('malware_family')\n",
                "    .agg(count('*').alias('infection_count'))\n",
                "    .withColumn('nodeType', lit('MalwareFamily'))\n",
                ")\n",
                "\n",
                "print(f'User nodes: {user_nodes_df.count()}')\n",
                "print(f'Device nodes: {device_nodes_df.count()}')\n",
                "print(f'Application nodes: {app_nodes_df.count()}')\n",
                "print(f'Breach nodes: {breach_nodes_df.count()}')\n",
                "print(f'Malware nodes: {malware_nodes_df.count()}')"
            ],
            "outputs": [],
            "execution_count": None
        },
        {
            "cell_type": "code",
            "metadata": {"tags": ["edges"]},
            "source": [
                "# Cell 4: Build edge DataFrames\n",
                "\n",
                "# User -> Breach (exposed_in)\n",
                "exposed_in_df = (\n",
                "    watchlist_df\n",
                "    .filter(col('source_id').isNotNull())\n",
                "    .select(\n",
                "        col('email').alias('user_email'),\n",
                "        col('source_id').alias('breach_id'),\n",
                "        col('severity'),\n",
                "        col('password_type'),\n",
                "        col('sighting'),\n",
                "        col('TimeGenerated')\n",
                "    )\n",
                "    .withColumn('edgeType', lit('exposed_in'))\n",
                ")\n",
                "\n",
                "# Device -> Malware (infected_by)\n",
                "infected_by_df = (\n",
                "    devices_df\n",
                "    .filter(col('malware_family').isNotNull())\n",
                "    .select(\n",
                "        col('user_hostname').alias('device_name'),\n",
                "        col('malware_family'),\n",
                "        col('infected_machine_id'),\n",
                "        col('TimeGenerated')\n",
                "    )\n",
                "    .withColumn('edgeType', lit('infected_by'))\n",
                "    .dropDuplicates(['device_name', 'malware_family'])\n",
                ")\n",
                "\n",
                "# User -> Application (has_stolen_creds_for)\n",
                "stolen_creds_df = (\n",
                "    compass_df\n",
                "    .select(\n",
                "        col('email').alias('user_email'),\n",
                "        col('target_domain'),\n",
                "        col('password_type'),\n",
                "        col('severity'),\n",
                "        col('TimeGenerated')\n",
                "    )\n",
                "    .withColumn('edgeType', lit('has_stolen_creds_for'))\n",
                "    .dropDuplicates(['user_email', 'target_domain'])\n",
                ")\n",
                "\n",
                "# User -> User (linked_to) via IdLink\n",
                "linked_to_df = (\n",
                "    idlink_df\n",
                "    .select(\n",
                "        col('source_email'),\n",
                "        col('target_email'),\n",
                "        col('link_type'),\n",
                "        col('confidence').alias('link_confidence'),\n",
                "        col('TimeGenerated')\n",
                "    )\n",
                "    .withColumn('edgeType', lit('linked_to'))\n",
                ")\n",
                "\n",
                "# User -> Device (used_device)\n",
                "used_device_df = (\n",
                "    devices_df\n",
                "    .filter(col('email').isNotNull())\n",
                "    .select(\n",
                "        col('email').alias('user_email'),\n",
                "        col('user_hostname').alias('device_name'),\n",
                "        col('TimeGenerated')\n",
                "    )\n",
                "    .withColumn('edgeType', lit('used_device'))\n",
                "    .dropDuplicates(['user_email', 'device_name'])\n",
                ")\n",
                "\n",
                "print(f'exposed_in edges: {exposed_in_df.count()}')\n",
                "print(f'infected_by edges: {infected_by_df.count()}')\n",
                "print(f'stolen_creds edges: {stolen_creds_df.count()}')\n",
                "print(f'linked_to edges: {linked_to_df.count()}')\n",
                "print(f'used_device edges: {used_device_df.count()}')"
            ],
            "outputs": [],
            "execution_count": None
        },
        {
            "cell_type": "code",
            "metadata": {"tags": ["graph-build"]},
            "source": [
                "# Cell 5: Build the SpyCloud Identity Graph\n",
                "from sentinel_graph.builders import GraphSpecBuilder\n",
                "\n",
                "builder = (GraphSpecBuilder.start()\n",
                "\n",
                "    # Node: Users (exposed identities)\n",
                "    .add_node('Users')\n",
                "        .from_dataframe(user_nodes_df.df)\n",
                "        .with_columns(\n",
                "            'email', 'max_severity', 'exposure_count', 'first_seen',\n",
                "            'display_name', 'nodeType',\n",
                "            key='email', display='display_name'\n",
                "        )\n",
                "\n",
                "    # Node: Devices (infected machines)\n",
                "    .add_node('Devices')\n",
                "        .from_dataframe(device_nodes_df.df)\n",
                "        .with_columns(\n",
                "            'user_hostname', 'os', 'browser', 'infection_count',\n",
                "            'primary_malware', 'nodeType',\n",
                "            key='user_hostname', display='user_hostname'\n",
                "        )\n",
                "\n",
                "    # Node: Applications (compromised apps)\n",
                "    .add_node('Applications')\n",
                "        .from_dataframe(app_nodes_df.df)\n",
                "        .with_columns(\n",
                "            'target_domain', 'stolen_cred_count', 'max_severity', 'nodeType',\n",
                "            key='target_domain', display='target_domain'\n",
                "        )\n",
                "\n",
                "    # Node: Breaches (data sources)\n",
                "    .add_node('Breaches')\n",
                "        .from_dataframe(breach_nodes_df.df)\n",
                "        .with_columns(\n",
                "            'breach_id', 'breach_title', 'breach_type', 'num_records',\n",
                "            'confidence', 'nodeType',\n",
                "            key='breach_id', display='breach_title'\n",
                "        )\n",
                "\n",
                "    # Node: MalwareFamilies\n",
                "    .add_node('MalwareFamilies')\n",
                "        .from_dataframe(malware_nodes_df.df)\n",
                "        .with_columns(\n",
                "            'malware_family', 'infection_count', 'nodeType',\n",
                "            key='malware_family', display='malware_family'\n",
                "        )\n",
                "\n",
                "    # Edge: exposed_in (User -> Breach)\n",
                "    .add_edge('exposed_in')\n",
                "        .from_dataframe(exposed_in_df.df)\n",
                "        .source(id_column='user_email', node_type='Users')\n",
                "        .target(id_column='breach_id', node_type='Breaches')\n",
                "        .with_columns(\n",
                "            'edgeType', 'severity', 'password_type', 'sighting', 'TimeGenerated',\n",
                "            key='edgeType', display='edgeType'\n",
                "        )\n",
                "\n",
                "    # Edge: infected_by (Device -> MalwareFamily)\n",
                "    .add_edge('infected_by')\n",
                "        .from_dataframe(infected_by_df.df)\n",
                "        .source(id_column='device_name', node_type='Devices')\n",
                "        .target(id_column='malware_family', node_type='MalwareFamilies')\n",
                "        .with_columns(\n",
                "            'edgeType', 'infected_machine_id', 'TimeGenerated',\n",
                "            key='edgeType', display='edgeType'\n",
                "        )\n",
                "\n",
                "    # Edge: has_stolen_creds_for (User -> Application)\n",
                "    .add_edge('has_stolen_creds_for')\n",
                "        .from_dataframe(stolen_creds_df.df)\n",
                "        .source(id_column='user_email', node_type='Users')\n",
                "        .target(id_column='target_domain', node_type='Applications')\n",
                "        .with_columns(\n",
                "            'edgeType', 'password_type', 'severity', 'TimeGenerated',\n",
                "            key='edgeType', display='edgeType'\n",
                "        )\n",
                "\n",
                "    # Edge: linked_to (User -> User)\n",
                "    .add_edge('linked_to')\n",
                "        .from_dataframe(linked_to_df.df)\n",
                "        .source(id_column='source_email', node_type='Users')\n",
                "        .target(id_column='target_email', node_type='Users')\n",
                "        .with_columns(\n",
                "            'edgeType', 'link_type', 'link_confidence', 'TimeGenerated',\n",
                "            key='edgeType', display='edgeType'\n",
                "        )\n",
                "\n",
                "    # Edge: used_device (User -> Device)\n",
                "    .add_edge('used_device')\n",
                "        .from_dataframe(used_device_df.df)\n",
                "        .source(id_column='user_email', node_type='Users')\n",
                "        .target(id_column='device_name', node_type='Devices')\n",
                "        .with_columns(\n",
                "            'edgeType', 'TimeGenerated',\n",
                "            key='edgeType', display='edgeType'\n",
                "        )\n",
                "\n",
                ").done()\n",
                "\n",
                "# Build the graph\n",
                "build_result = builder.build_graph_with_data()\n",
                "print(f'Graph build status: {build_result.get(\"status\")}')"
            ],
            "outputs": [],
            "execution_count": None
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## Sample Graph Queries\n",
                "\n",
                "The following GQL queries demonstrate how to explore the SpyCloud identity graph.\n",
                "These queries work with both ephemeral and materialized graphs."
            ]
        },
        {
            "cell_type": "code",
            "metadata": {"tags": ["queries"]},
            "source": [
                "# Cell 6: Query - High-severity users and their blast radius\n",
                "query_high_risk = \"\"\"\n",
                "MATCH (u:Users)-[e]->(target)\n",
                "WHERE u.max_severity >= 25\n",
                "RETURN u, e, target\n",
                "LIMIT 100\n",
                "\"\"\"\n",
                "builder.query(query_high_risk).show()\n",
                "print('Showing high-severity exposed users and all connected nodes')"
            ],
            "outputs": [],
            "execution_count": None
        },
        {
            "cell_type": "code",
            "metadata": {},
            "source": [
                "# Cell 7: Query - Users with stolen credentials for critical applications\n",
                "query_critical_apps = \"\"\"\n",
                "MATCH (u:Users)-[c:has_stolen_creds_for]->(a:Applications)\n",
                "WHERE a.stolen_cred_count > 5\n",
                "RETURN u, c, a\n",
                "LIMIT 50\n",
                "\"\"\"\n",
                "builder.query(query_critical_apps).show()\n",
                "print('Applications with the most stolen credentials')"
            ],
            "outputs": [],
            "execution_count": None
        },
        {
            "cell_type": "code",
            "metadata": {},
            "source": [
                "# Cell 8: Query - Device infection chains (Device -> Malware -> Device)\n",
                "query_infection_chain = \"\"\"\n",
                "MATCH (d:Devices)-[i:infected_by]->(m:MalwareFamilies)\n",
                "WHERE m.infection_count > 3\n",
                "RETURN d, i, m\n",
                "LIMIT 50\n",
                "\"\"\"\n",
                "builder.query(query_infection_chain).show()\n",
                "print('Malware families with the most device infections')"
            ],
            "outputs": [],
            "execution_count": None
        },
        {
            "cell_type": "code",
            "metadata": {},
            "source": [
                "# Cell 9: Query - Identity link chains (find connected personas)\n",
                "query_identity_links = \"\"\"\n",
                "MATCH (u1:Users)-[l:linked_to]->(u2:Users)-[e:exposed_in]->(b:Breaches)\n",
                "RETURN u1, l, u2, e, b\n",
                "LIMIT 50\n",
                "\"\"\"\n",
                "builder.query(query_identity_links).show()\n",
                "print('Identity link chains showing connected personas and their breach exposure')"
            ],
            "outputs": [],
            "execution_count": None
        },
        {
            "cell_type": "code",
            "metadata": {},
            "source": [
                "# Cell 10: Query - Full attack path: User -> Device -> Malware -> Other Devices\n",
                "query_attack_path = \"\"\"\n",
                "MATCH path = (u:Users)-[:used_device]->(d:Devices)-[:infected_by]->(m:MalwareFamilies)\n",
                "WHERE u.max_severity >= 20\n",
                "RETURN path\n",
                "LIMIT 30\n",
                "\"\"\"\n",
                "builder.query(query_attack_path).show()\n",
                "print('Attack paths: User -> infected Device -> Malware Family')"
            ],
            "outputs": [],
            "execution_count": None
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## Materialize the Graph\n",
                "\n",
                "To persist this graph and enable scheduled refreshes:\n",
                "\n",
                "1. In VS Code, select **Create Scheduled Job** > **Create a graph job**\n",
                "2. Name: `SpyCloud-Identity-Exposure-Graph`\n",
                "3. Description: `Models SpyCloud identity exposures, device infections, and credential theft relationships`\n",
                "4. Schedule: **Daily** at 02:00 UTC (after SpyCloud data sync)\n",
                "5. Click **Submit**\n",
                "\n",
                "Once materialized, query this graph from:\n",
                "- Sentinel Graph Query editor in Azure Portal\n",
                "- Sentinel Graph MCP Server (for AI agent queries)\n",
                "- Advanced Hunting with GQL\n",
                "\n",
                "### Sentinel Graph MCP Server Integration\n",
                "\n",
                "After materializing, use the Sentinel Graph MCP tools for AI-powered analysis:\n",
                "\n",
                "```\n",
                "# In VS Code with GitHub Copilot:\n",
                "# 1. Ctrl+Shift+P > Add MCP Server > HTTP\n",
                "# 2. URL: https://sentinel.microsoft.com/mcp/graph\n",
                "# 3. Name: Sentinel Graph MCP Server\n",
                "#\n",
                "# Then ask:\n",
                "# - \"What is the blast radius of user@company.com?\"\n",
                "# - \"Show attack paths from user@company.com to our key vaults\"\n",
                "# - \"What is the exposure perimeter of our SQL servers?\"\n",
                "```"
            ]
        }
    ]
}

with open(notebook_path, 'w') as f:
    json.dump(notebook, f, indent=2)

print(f'Notebook written to: {notebook_path}')
PYEOF

  ok "Generated notebook: $notebook_path"
  info "Open in VS Code with Microsoft Sentinel extension to use"
}

# ==============================================================================
# GENERATE MCP SERVER CONFIGURATION
# ==============================================================================
generate_mcp_config() {
  step "Generating Sentinel Graph MCP Configuration"

  local mcp_config_path="${OUTPUT_DIR}/.vscode/mcp.json"
  mkdir -p "${OUTPUT_DIR}/.vscode"

  cat > "$mcp_config_path" << 'MCPEOF'
{
  "servers": {
    "Sentinel graph MCP Server": {
      "type": "http",
      "url": "https://sentinel.microsoft.com/mcp/graph",
      "headers": {}
    }
  }
}
MCPEOF

  ok "Generated MCP config: $mcp_config_path"
  info "Add to VS Code workspace for GitHub Copilot graph queries"
  echo ""
  info "Available MCP tools:"
  echo "  - graph_exposure_perimeter: Find how accessible a node is"
  echo "  - graph_find_blastRadius: Evaluate impact if a node is compromised"
  echo "  - graph_find_walkable_paths: Find attack paths between nodes (up to 4 hops)"
  echo ""
  info "Example prompts for GitHub Copilot:"
  echo '  "What is the blast radius of user@company.com?"'
  echo '  "Show paths from compromised-user to our key vaults"'
  echo '  "Which nodes have the highest exposure perimeter?"'
}

# ==============================================================================
# FULL SETUP
# ==============================================================================
full_setup() {
  step "Full Sentinel Graph Setup"

  validate_prerequisites
  generate_notebook
  generate_mcp_config

  echo ""
  step "Setup Complete"
  echo ""
  info "Next steps:"
  echo "  1. Open SpyCloud-Identity-Graph.ipynb in VS Code with Sentinel extension"
  echo "  2. Select kernel: Microsoft Sentinel > Medium graph pool"
  echo "  3. Update workspace name in Cell 2"
  echo "  4. Run all cells to build ephemeral graph"
  echo "  5. Materialize graph for persistent use (Create Scheduled Job)"
  echo "  6. Configure MCP server in VS Code for AI-powered graph queries"
  echo ""
  info "MCP Server URL: https://sentinel.microsoft.com/mcp/graph"
  echo ""
  info "Documentation:"
  echo "  Custom Graphs: https://learn.microsoft.com/azure/sentinel/datalake/custom-graphs"
  echo "  Graph MCP Tools: Available in Sentinel Graph private preview"
}

# ==============================================================================
# MAIN
# ==============================================================================
banner

case "$MODE" in
  setup) full_setup;;
  notebook) generate_notebook;;
  mcp-config) generate_mcp_config;;
  validate) validate_prerequisites;;
  *) echo "Unknown mode: $MODE"; exit 1;;
esac
