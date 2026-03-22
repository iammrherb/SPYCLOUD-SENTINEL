# Repository Structure

## Overview

This repository contains two independent deployment paths for SpyCloud Identity Exposure Intelligence for Microsoft Sentinel:

1. **Content Hub / Marketplace** (`Solutions/`) - Content-only package for Sentinel Content Hub
2. **Deploy to Azure** (`deploy/`) - Full infrastructure deployment with advanced options

## Directory Layout

```
SPYCLOUD-SENTINEL/
|-- Solutions/                          # Content Hub / Marketplace package
|   |-- SpyCloud Identity Exposure Intelligence/
|       |-- Package/
|       |   |-- mainTemplate.json       # Content Hub ARM template (content only)
|       |   |-- createUiDefinition.json # Content Hub install wizard
|       |   |-- testParameters.json     # Test parameters for validation
|       |-- Analytic Rules/             # Detection rule YAML templates
|       |-- Data/                       # Solution catalog data
|       |-- Data Connectors/            # Data connector definitions
|       |-- Hunting Queries/            # KQL hunting queries
|       |-- Playbooks/                  # Logic App playbook ARM templates
|       |   |-- Custom Connector/       # SpyCloud API custom connector
|       |   |-- SpyCloud-<Name>/        # Standalone playbook (azuredeploy.json)
|       |   |-- SpyCloud-<Name>-Template/ # Content Hub wrapper template
|       |-- Workbooks/                  # Sentinel workbook definitions
|       |-- SolutionMetadata.json       # Package metadata for Content Hub
|       |-- readme.md                   # Solution readme
|
|-- deploy/                             # Full ARM infrastructure deployment
|   |-- azuredeploy.json               # Full deployment template (158+ resources)
|   |-- azuredeploy.parameters.json    # Parameter file
|   |-- createUiDefinition.json        # Deployment wizard UI
|   |-- post-deploy.sh                 # Post-deployment configuration script
|   |-- post-deploy-auto.sh            # Automated post-deployment script
|   |-- functions/                     # Azure Functions source code
|   |   |-- SpyCloudEnrichment/        # Main enrichment function
|   |   |-- SpyCloudAIEngine/          # AI investigation engine
|   |-- terraform/                     # Terraform alternative deployment
|
|-- content/                            # Sentinel CI/CD auto-deploy content
|   |-- playbooks/                     # ARM-wrapped playbook templates
|   |-- workbooks/                     # ARM-wrapped workbook templates
|   |-- analytics-rules/              # Analytics rule YAML definitions
|   |-- automations/                   # Automation rule templates
|   |-- hunting-queries/              # Hunting query definitions
|
|-- copilot/                           # Security Copilot agent & plugin
|-- mcp-server/                        # MCP server for AI integrations
|-- notebooks/                         # Jupyter notebooks
|-- portal/                            # Web-based documentation portal
|-- scripts/                           # Deployment & toolkit scripts
|-- docs/                              # Documentation
|-- .github/workflows/                 # CI/CD workflows
|-- sentinel-deployment.config         # Sentinel auto-deploy exclusion config
```

## Deployment Paths Explained

### Path 1: Content Hub / Marketplace

**Location:** `Solutions/SpyCloud Identity Exposure Intelligence/Package/`

**What it deploys:** Content only (no infrastructure)
- 38 analytics rules
- 23 playbooks (as Logic App templates)
- 3+ workbooks
- 1 data connector definition
- 1 hunting query

**How to install:**
1. Go to Microsoft Sentinel > Content Hub
2. Search for "SpyCloud"
3. Click Install

**What it does NOT deploy:**
- Function Apps
- Key Vault
- App Service
- Custom log tables (DCR/DCE)
- These must be deployed separately via Path 2 or manually configured

### Path 2: Deploy to Azure (Full Infrastructure)

**Location:** `deploy/`

**What it deploys:** Complete infrastructure + content
- Everything in Path 1, plus:
- Azure Function App (SpyCloud API enrichment + AI engine)
- Key Vault (API key storage)
- Data Collection Rules & Endpoints
- Custom log tables (SpyCloud_Breach_CL, etc.)
- App Service (optional)
- RBAC role assignments
- Managed identity configuration

**How to deploy:**
1. Click the "Deploy to Azure" button in the README
2. Or use Azure Cloud Shell: `az deployment group create --template-file deploy/azuredeploy.json`
3. Or use Terraform: `cd deploy/terraform && terraform apply`

### Path 3: Sentinel CI/CD Auto-Deploy

**Location:** `content/`

**What it does:** Automatically deploys content changes to a connected Sentinel workspace when files in `content/playbooks/` or `content/workbooks/` are modified.

**Configuration:** `sentinel-deployment.config` controls which files are included/excluded from auto-deployment.

## Key Differences

| Feature | Content Hub (Solutions/) | Deploy to Azure (deploy/) |
|---------|------------------------|--------------------------|
| Analytics Rules | Yes (38) | Yes (38) |
| Playbooks | Yes (23 Logic Apps) | Yes (23+) |
| Workbooks | Yes (3+) | Yes (3+) |
| Data Connector | Definition only | Full with DCR/DCE |
| Function App | No | Yes |
| Key Vault | No | Yes |
| Custom Tables | No | Yes |
| AI Engine | No | Yes |
| Terraform | No | Yes |
| Post-Deploy Script | No | Yes |

## API Support

Both deployment paths support all SpyCloud APIs through the playbooks:
- **Breach API** - Breach catalog and watchlist data
- **Compass API** - Identity exposure scoring
- **Investigations API** - Deep investigation lookups
- **IdLink API** - Identity correlation
- **Exposure API** - Exposure assessment

The Content Hub path uses a **Custom Connector** (`Solutions/.../Playbooks/Custom Connector/`) for API access. The Deploy to Azure path uses **Azure Functions** (`deploy/functions/`) for server-side API enrichment.
