# SpyCloud Identity Exposure Intelligence for Sentinel — Deployment Guide

> **Version 2.0** | All deployment options with step-by-step instructions

## Prerequisites

### Required

- Azure subscription with Sentinel-enabled Log Analytics workspace
- SpyCloud Enterprise API key (from [portal.spycloud.io](https://portal.spycloud.io))
- Azure AD Global Admin or Security Admin role (for initial setup)
- Microsoft Sentinel Contributor role

### Optional (for full feature set)

- SpyCloud Compass API key (endpoint threat protection)
- SpyCloud SIP API key (session identity protection)
- SpyCloud Investigations API key (deep threat hunting)
- OpenAI API key or Azure OpenAI deployment (AI Investigation Engine)
- Microsoft Purview license (compliance assessment)

### Azure Resource Providers

Ensure these are registered in your subscription:

```bash
az provider register --namespace Microsoft.OperationalInsights
az provider register --namespace Microsoft.SecurityInsights
az provider register --namespace Microsoft.Logic
az provider register --namespace Microsoft.Web
```

---

## Option 1: Deploy to Azure (One-Click)

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json)

[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fiammrherb%2FSPYCLOUD-SENTINEL%2Fmain%2FcreateUiDefinition.json)

### Wizard Steps

**Step 1 — Basics**
- Select your subscription and resource group
- Choose the region matching your Log Analytics workspace

**Step 2 — Workspace Configuration**
- Select existing Log Analytics workspace
- Verify Sentinel is enabled on the workspace

**Step 3 — SpyCloud API Configuration**
- Enter your Enterprise API key (required)
- Select minimum severity threshold (2, 5, 20, or 25)
- Configure polling interval (default: 40 minutes)
- Optionally enter Compass, SIP, Investigations API keys
- Enter monitored domain (required for SIP, Investigations, IdLink pollers)

**Step 4 — Response Configuration**
- Enable/disable playbook categories:
  - Core Remediation (password reset, session revoke, device isolate)
  - Notification (email, Slack, Teams, webhook)
  - ITSM (Jira, ServiceNow)
  - Advanced (MFA enforce, CA block, firewall, OAuth revoke)
- Configure notification endpoints (email addresses, webhook URLs)

**Step 5 — AI Engine (Optional)**
- Enable AI Investigation Engine
- Select provider: OpenAI or Azure OpenAI
- Enter API key and model configuration
- Configure Purview integration (account name, label ID)

**Step 6 — Advanced Settings**
- Enable/disable specific analytics rule categories
- Configure workbook deployment
- Set up automation rules
- KeyVault integration settings

**Step 7 — Review + Create**
- Review all settings
- Click "Create" to deploy

### Post-Deployment (Required)

After the ARM template completes, complete these steps:

1. **Activate the Data Connector**
   - Navigate to Sentinel > Data connectors
   - Find "SpyCloud Identity Exposure Intelligence"
   - Click "Open connector page" > "Connect"
   - Verify data starts flowing within 40 minutes

2. **Grant Managed Identity Permissions**
   ```bash
   # Run the post-deployment script
   curl -sL https://raw.githubusercontent.com/iammrherb/SPYCLOUD-SENTINEL/main/scripts/grant-permissions.sh | bash
   ```
   Or use the toolkit: `./scripts/spycloud-toolkit.sh --fix-permissions`

3. **Enable Analytics Rules**
   - Navigate to Sentinel > Analytics
   - Find SpyCloud rule templates
   - Enable rules matching your severity threshold

4. **Configure Automation Rules**
   - Navigate to Sentinel > Automation
   - Review and enable auto-enrichment rules
   - Assign playbooks to automation rules

---

## Option 2: Azure CloudShell Deployment

```bash
# Clone the repository
git clone https://github.com/iammrherb/SPYCLOUD-SENTINEL.git
cd SPYCLOUD-SENTINEL

# Run the CloudShell deployment script
bash scripts/deploy-cloudshell.sh
```

The CloudShell script provides an interactive wizard:
1. Prompts for subscription, resource group, and workspace
2. Validates prerequisites automatically
3. Accepts an answer file for non-interactive deployment:
   ```bash
   bash scripts/deploy-cloudshell.sh --answer-file my-config.json
   ```

### Answer File Format

```json
{
  "subscriptionId": "your-subscription-id",
  "resourceGroupName": "rg-spycloud-sentinel",
  "workspaceName": "law-sentinel-prod",
  "location": "eastus",
  "spycloudApiKey": "your-api-key",
  "minimumSeverity": 2,
  "pollingInterval": 40,
  "enableCompass": false,
  "enableSIP": false,
  "enableAIEngine": true,
  "aiProvider": "openai",
  "aiApiKey": "sk-..."
}
```

---

## Option 3: Terraform Deployment

```bash
cd terraform/

# Initialize Terraform
terraform init

# Create terraform.tfvars from example
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

# Plan and review
terraform plan

# Deploy
terraform apply
```

### Key Terraform Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `subscription_id` | Yes | Azure subscription ID |
| `resource_group_name` | Yes | Target resource group |
| `workspace_name` | Yes | Log Analytics workspace name |
| `spycloud_api_key` | Yes | SpyCloud Enterprise API key |
| `location` | No | Azure region (default: eastus) |
| `enable_compass` | No | Enable Compass integration |
| `enable_sip` | No | Enable SIP integration |
| `enable_ai_engine` | No | Enable AI Investigation Engine |
| `environment` | No | "commercial" or "government" |

### Azure Government

```bash
# Set environment variable
export ARM_ENVIRONMENT=usgovernment

# Or in terraform.tfvars
environment = "government"
```

---

## Option 4: GitHub Actions CI/CD

The repository includes production-ready GitHub Actions workflows.

### Workflow: sentinel-deploy.yml

**Triggers:**
- Push to `main` branch (production deploy)
- Manual `workflow_dispatch` (any environment)
- Pull request (validation only)

**Jobs:**

| Job | Purpose | Duration |
|-----|---------|----------|
| `validate` | ARM template validation, JSON schema check | ~2 min |
| `arm-ttk` | Azure Resource Manager Template Toolkit tests | ~3 min |
| `package` | Build Content Hub package (.zip) | ~1 min |
| `deploy-staging` | Deploy to staging workspace | ~5 min |
| `smoke-test` | Verify deployment succeeded | ~2 min |
| `deploy-production` | Deploy to production (manual approval) | ~5 min |
| `rollback` | Auto-rollback on failure | ~3 min |

**Required GitHub Secrets:**

| Secret | Description |
|--------|-------------|
| `AZURE_CREDENTIALS` | Service principal JSON for Azure login |
| `SPYCLOUD_API_KEY` | SpyCloud Enterprise API key |
| `STAGING_RESOURCE_GROUP` | Staging environment resource group |
| `STAGING_WORKSPACE` | Staging Log Analytics workspace |
| `PROD_RESOURCE_GROUP` | Production resource group |
| `PROD_WORKSPACE` | Production Log Analytics workspace |

**Setting Up Azure Credentials:**

```bash
# Create service principal with Contributor role
az ad sp create-for-rbac \
  --name "spycloud-sentinel-cicd" \
  --role contributor \
  --scopes /subscriptions/{subscription-id}/resourceGroups/{resource-group} \
  --sdk-auth

# Copy the JSON output to GitHub secret AZURE_CREDENTIALS
```

### Workflow: pr-validation.yml

Runs on every pull request:
- ARM template syntax validation
- JSON schema validation
- Python syntax check (Function Apps)
- Node.js syntax check (MCP Server)
- Content Hub package validation

---

## Option 5: Content Hub Installation

1. Navigate to **Microsoft Sentinel** > **Content Hub**
2. Search for "SpyCloud Identity Exposure Intelligence"
3. Click **Install**
4. Configure parameters in the installation wizard
5. Click **Create**

> **Note:** Content Hub installation deploys analytics rules, hunting queries, and workbooks. Playbooks and the data connector require separate ARM deployment.

---

## Verification

After any deployment method, verify the installation:

```bash
# Run the toolkit health check
bash scripts/spycloud-toolkit.sh --health-check

# Or manually verify:
# 1. Check data connector status in Sentinel
# 2. Verify custom tables exist in Log Analytics
# 3. Check playbook connections in Logic Apps
# 4. Review analytics rules in Sentinel > Analytics
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|---------|
| No data in tables | Connector not activated | Go to Data connectors > Connect |
| Playbook failures | Missing permissions | Run `./scripts/spycloud-toolkit.sh --fix-permissions` |
| API rate limiting | Too frequent polling | Increase polling interval to 60+ minutes |
| ARM deployment fails | Region not supported | Try eastus, westus2, or westeurope |
| AI Engine errors | Missing API key | Verify OPENAI_API_KEY in Function App settings |
| Purview label errors | Graph API not configured | Add InformationProtection.Policy.Read.All scope |

### Diagnostic KQL Queries

```kql
// Check data ingestion health
SpyCloudBreachWatchlist_CL
| summarize LastRecord = max(TimeGenerated), RecordCount = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated desc
| take 24

// Check enrichment audit trail
SpyCloudEnrichmentAudit_CL
| summarize count() by action_s, bin(TimeGenerated, 1h)
| order by TimeGenerated desc

// Check playbook execution status
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.LOGIC"
| where resource_workflowName_s startswith "SpyCloud"
| summarize count() by resource_workflowName_s, status_s
| order by count_ desc
```

### Support

- **SpyCloud Support:** support@spycloud.com
- **GitHub Issues:** [github.com/iammrherb/SPYCLOUD-SENTINEL/issues](https://github.com/iammrherb/SPYCLOUD-SENTINEL/issues)
- **Documentation:** See `docs/` directory for detailed guides
